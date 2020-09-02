package filter

import (
	"fmt"
	"net/http"
	"sync"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"
)

// Manager describe one filter map (client id: filters)
type Manager struct {
	idHeaderName string
	matchMemMap  map[string][][]*labels.Matcher
	injectMemMap map[string][]*labels.Matcher
	logger       kitlog.Logger
	mtx          sync.RWMutex
}

// NewManager creates new instance
func NewManager(l *kitlog.Logger) *Manager {
	fm := &Manager{
		idHeaderName: "",
		matchMemMap:  make(map[string][][]*labels.Matcher),
		injectMemMap: make(map[string][]*labels.Matcher),
		logger:       *l,
	}
	return fm
}

// ApplyConfig apply new config
func (fm *Manager) ApplyConfig(idHeaderName string, matchMap map[string][]string, injectMap map[string]string) error {
	fm.mtx.Lock()
	defer fm.mtx.Unlock()

	if (len(matchMap) == 0 && len(injectMap) == 0) || idHeaderName == "" {
		return fmt.Errorf("wrong filter config")
	}

	if len(matchMap) > 0 {
		matchMemMap := make(map[string][][]*labels.Matcher)
		var matcherSets [][]*labels.Matcher
		for id, matches := range matchMap {
			matcherSets = make([][]*labels.Matcher, 0)
			for _, s := range matches {
				matchers, err := promql.ParseMetricSelector(s)
				if err != nil {
					return err
				}
				matcherSets = append(matcherSets, matchers)
			}
			matchMemMap[id] = matcherSets
			level.Debug(fm.logger).Log("client.id", id, "matchset", fmt.Sprintf("%v", matchMemMap[id]))
		}
		fm.matchMemMap = matchMemMap
	}

	if len(injectMap) > 0 {
		injectMemMap := make(map[string][]*labels.Matcher)
		for id, s := range injectMap {
			inject, err := promql.ParseMetricSelector(s)
			if err != nil {
				return err
			}
			injectMemMap[id] = inject
			level.Debug(fm.logger).Log("client.id", id, "inject", fmt.Sprintf("%v", injectMemMap[id]))
		}
		fm.injectMemMap = injectMemMap
	}

	fm.idHeaderName = idHeaderName
	return nil
}

// CopyConfig apply new config from another manager
func (fm *Manager) CopyConfig(manager *Manager) error {
	fm.mtx.Lock()
	defer fm.mtx.Unlock()

	if (len(manager.matchMemMap) == 0 && len(manager.injectMemMap) == 0) || manager.idHeaderName == "" {
		return fmt.Errorf("wrong filter config")
	}

	fm.idHeaderName = manager.idHeaderName
	fm.matchMemMap = manager.matchMemMap
	fm.injectMemMap = manager.injectMemMap

	return nil
}

// FilterQuery filter query parameter
func (fm *Manager) FilterQuery(parameter string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		rID := r.Header.Get(fm.idHeaderName)
		if rID == "" {
			http.Error(w, fmt.Sprintf("ERROR: Empty header %v", fm.idHeaderName), http.StatusBadRequest)
			level.Warn(fm.logger).Log("msg", "empty header in filter request", "value", fm.idHeaderName)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("ERROR: error parsing form values: %v", err), http.StatusBadRequest)
			level.Warn(fm.logger).Log("msg", "cannot parse form values", "id", rID, "err", err)
			return
		}

		filteredQuery, err := fm.labelsParseAndFilter(r.Form[parameter], rID)
		if err != nil {
			level.Warn(fm.logger).Log("msg", "cannot parse query", "id", rID, "err", err)
		}

		if len(filteredQuery) == 0 {
			http.Error(w, fmt.Sprintf("Wrong query. You should use one of these sets %v", fm.matchMemMap[rID]), http.StatusForbidden)
			level.Warn(fm.logger).Log("msg", "filter result is empty", "id", rID, "value", fmt.Sprintf("%v", r.Form["match[]"]))
			return
		}
		// clean and fill form
		r.Form.Del(parameter)
		for _, i := range filteredQuery {
			r.Form.Add(parameter, i)
		}

		h.ServeHTTP(w, r)
	})
}

func (fm *Manager) labelsParseAndFilter(queries []string, rID string) ([]string, error) {
	filteredQueries := make([]string, 0)
	level.Debug(fm.logger).Log("msg", "request sets", "id", rID, "value", fmt.Sprintf("%v", queries))
	for _, s := range queries {
		expr, err := promql.ParseExpr(s)
		if err != nil {
			return filteredQueries, err
		}
		if len(fm.injectMemMap[rID]) > 0 {
			// lets try just to add injected Matchers
			if err = promql.Walk(inspector(injectLabels(fm.injectMemMap[rID])), expr, nil); err != nil {
				return nil, err
			}
		}
		if len(fm.matchMemMap[rID]) > 0 {
			if err = promql.Walk(inspector(checkLabels(fm.matchMemMap[rID])), expr, nil); err != nil {
				level.Debug(fm.logger).Log("msg", "check labels error", "id", rID, "err", err)
				continue
			}
		}
		s = expr.String()
		filteredQueries = append(filteredQueries, s)
	}
	return filteredQueries, nil
}

type inspector func(promql.Node, []promql.Node) error

func (f inspector) Visit(node promql.Node, path []promql.Node) (promql.Visitor, error) {
	if err := f(node, path); err != nil {
		return nil, err
	}
	return f, nil
}

func checkLabels(matchMemSet [][]*labels.Matcher) func(node promql.Node, path []promql.Node) error {
	return func(node promql.Node, path []promql.Node) error {
		switch n := node.(type) {
		case *promql.VectorSelector:
			for _, mm := range matchMemSet {
				if matchIntersection(n.LabelMatchers, mm) {
					return nil
				}
			}
			return fmt.Errorf("not match %v", matchMemSet)
		case *promql.MatrixSelector:
			for _, mm := range matchMemSet {
				if matchIntersection(n.LabelMatchers, mm) {
					return nil
				}
			}
			return fmt.Errorf("not match %v", matchMemSet)
		}
		return nil
	}
}

func injectLabels(injectMemSet []*labels.Matcher) func(node promql.Node, path []promql.Node) error {
	return func(node promql.Node, path []promql.Node) error {
		switch n := node.(type) {
		case *promql.VectorSelector:
			n.LabelMatchers = append(n.LabelMatchers, injectMemSet...)
		case *promql.MatrixSelector:
			n.LabelMatchers = append(n.LabelMatchers, injectMemSet...)
		}
		return nil
	}
}

func matchIntersection(mr, mm []*labels.Matcher) bool {
	count := 0
	for _, mri := range mr {
		for _, mmi := range mm {
			if suitMatchers(mri, mmi) {
				count++
			}
			if count == len(mm) {
				return true
			}
		}
	}
	return false
}

func suitMatchers(mri, mmi *labels.Matcher) bool {
	switch mmi.Type.String() + mri.Type.String() {
	case "!==":
		return mmi.Matches(mri.Value)
	case "=~=":
		return mmi.Matches(mri.Value)
	case "=~=~":
		return mmi.Matches(mri.Value)
	case "!~=":
		return mmi.Matches(mri.Value)
	// case "!~=~":
	// return mmi.Matches(mri.Value)
	// case "!~!=":
	// match, _ := regexp.MatchString(mmi.Value, mri.Value)
	// return match
	default:
		return mri.Name == mmi.Name &&
			mri.Type == mmi.Type &&
			mri.Value == mmi.Value
	}
}
