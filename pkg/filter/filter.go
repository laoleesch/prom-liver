package filter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	v1 "github.com/prometheus/client_golang/api/prometheus/v1"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/prometheus/model/labels"
	parser "github.com/prometheus/prometheus/promql/parser"

	remote "github.com/laoleesch/prom-liver/pkg/remote"
)

// Manager describe one filter map (client id: filters)
type Manager struct {
	idHeaderName string
	injectMemMap map[string][]*labels.Matcher
	filterMemMap map[string][][]*labels.Matcher
	checkOnly    bool

	logger kitlog.Logger
	mtx    sync.RWMutex
}

// NewManager creates new instance
func NewManager(l *kitlog.Logger) *Manager {
	fm := &Manager{
		idHeaderName: "",
		injectMemMap: make(map[string][]*labels.Matcher),
		filterMemMap: make(map[string][][]*labels.Matcher),
		checkOnly:    false,

		logger: *l,
	}
	return fm
}

// ApplyConfig apply new config
func (fm *Manager) ApplyConfig(idHeaderName string, injectMap map[string]string, filterMap map[string][]string, checkOnly bool) error {
	fm.mtx.Lock()
	defer fm.mtx.Unlock()

	if (len(injectMap)+len(filterMap) == 0) || idHeaderName == "" {
		return fmt.Errorf("wrong filter config")
	}

	if len(injectMap) > 0 {
		injectMemMap := make(map[string][]*labels.Matcher)
		for id, s := range injectMap {
			inject, err := parser.ParseMetricSelector(s)
			if err != nil {
				return err
			}
			injectMemMap[id] = inject
			level.Debug(fm.logger).Log("client.id", id, "inject", fmt.Sprintf("%v", injectMemMap[id]))
		}
		fm.injectMemMap = injectMemMap
	}

	if len(filterMap) > 0 {
		filterMemMap := make(map[string][][]*labels.Matcher)
		var matcherSets [][]*labels.Matcher
		for id, matches := range filterMap {
			matcherSets = make([][]*labels.Matcher, 0)
			for _, s := range matches {
				matchers, err := parser.ParseMetricSelector(s)
				if err != nil {
					return err
				}
				matcherSets = append(matcherSets, matchers)
			}
			filterMemMap[id] = matcherSets
			level.Debug(fm.logger).Log("client.id", id, "filterset", fmt.Sprintf("%v", filterMemMap[id]))
		}
		fm.filterMemMap = filterMemMap
	}

	fm.idHeaderName = idHeaderName
	fm.checkOnly = checkOnly
	return nil
}

// CopyConfig apply new config from another manager
func (fm *Manager) CopyConfig(manager *Manager) error {
	fm.mtx.Lock()
	defer fm.mtx.Unlock()

	if (len(manager.injectMemMap)+len(manager.filterMemMap) == 0) || manager.idHeaderName == "" {
		return fmt.Errorf("wrong filter config")
	}

	fm.idHeaderName = manager.idHeaderName
	fm.injectMemMap = manager.injectMemMap
	fm.filterMemMap = manager.filterMemMap

	fm.checkOnly = manager.checkOnly

	return nil
}

// FilterMatch filter requests with multiple []match through reverse-proxy
func (fm *Manager) FilterMatch(rmp *remote.Manager) http.Handler {
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

		params := r.Form["match[]"]
		if len(params) == 0 {
			params = []string{"{__name__!=''}"}
		}

		filteredQueries, err := fm.labelsParseAndFilter(params, rID)
		if err != nil {
			level.Warn(fm.logger).Log("msg", "error on parse and filter query", "id", rID, "err", err)
		}
		if fm.checkOnly && len(filteredQueries) == 0 {
			http.Error(w, remote.ErrorAPIResponse(v1.ErrClient, fmt.Errorf("Acces denied. Allowed labels sets: %v", fm.filterMemMap[rID])).String(), http.StatusForbidden)
			return

		}

		q := r.URL.Query()
		q.Del("match[]")
		r.Form.Del("match[]")
		for _, i := range filteredQueries {
			q.Add("match[]", i)
		}
		r.URL.RawQuery = q.Encode()
		rmp.ServeReverseProxy(w, r)

	})
}

// FilterQuery filter query parameter
func (fm *Manager) FilterQuery(rmp *remote.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		rID := r.Header.Get(fm.idHeaderName)
		ctx := r.Context()

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
		params := r.Form["query"]
		if len(params) == 0 {
			params = []string{"{__name__!=''}"}
		}

		filteredQueries, err := fm.labelsParseAndFilter(params, rID)
		if err != nil {
			http.Error(w, remote.ErrorAPIResponse(v1.ErrBadData, err).String(), http.StatusBadRequest)
			return
		}
		level.Debug(fm.logger).Log("msg", "got filters:", "id", rID, "value", fmt.Sprintf("%v", filteredQueries))

		if fm.checkOnly && len(filteredQueries) == 0 {
			http.Error(w, remote.ErrorAPIResponse(v1.ErrClient, fmt.Errorf("Acces denied. Allowed labels sets: %v", fm.filterMemMap[rID])).String(), http.StatusForbidden)
			return

		} else if len(filteredQueries) == 1 {
			q := r.URL.Query()
			r.Form.Del("query")
			q.Set("query", filteredQueries[0])
			r.URL.RawQuery = q.Encode()
			rmp.ServeReverseProxy(w, r)
			return
		}

		mData, err := rmp.FetchMultiQueryResult(ctx, r.URL.EscapedPath(), r.URL.Query(), filteredQueries)
		if err != nil {
			if errors.Is(err, remote.ErrorRemoteStatusCode) {
				status := http.StatusInternalServerError
				switch err {
				case remote.ErrorRemoteStatus400:
					status = http.StatusBadRequest
				case remote.ErrorRemoteStatus422:
					status = http.StatusUnprocessableEntity
				case remote.ErrorRemoteStatus503:
					status = http.StatusServiceUnavailable
				default:
					status = http.StatusInternalServerError
				}
				http.Error(w, mData.String(), status)
				return

			}
			http.Error(w, fmt.Sprintf("ERROR: error getting data: %v", err), http.StatusInternalServerError)
			level.Error(fm.logger).Log("msg", "error getting data", "id", rID, "err", err)
			return
		}

		b, _ := json.Marshal(mData)
		_, err = w.Write(b)
		if err != nil {
			http.Error(w, fmt.Sprintf("ERROR: error send data: %v", err), http.StatusInternalServerError)
			level.Error(fm.logger).Log("msg", "error send data", "id", rID, "err", err)
			return
		}

	})
}

func (fm *Manager) labelsParseAndFilter(queries []string, rID string) ([]string, error) {
	filteredQueries := make([]string, 0)

	level.Debug(fm.logger).Log("msg", "request sets", "id", rID, "value", fmt.Sprintf("%v", queries))
	for _, s := range queries {
		expr, err := parser.ParseExpr(s)
		if err != nil {
			return nil, err
		}
		if len(fm.injectMemMap[rID]) > 0 {
			if err = parser.Walk(inspector(injectLabels(fm.injectMemMap[rID])), expr, nil); err != nil {
				return nil, err
			}
			s = expr.String()
		}

		if len(fm.filterMemMap[rID]) > 0 {
			if err = parser.Walk(inspector(checkLabels(fm.filterMemMap[rID])), expr, nil); err != nil {
				// if err then not match

				// if check_only then go next
				if fm.checkOnly {
					continue
				}

				// create subquery with injects
				subqueries := make([]string, 0)
				for _, inj := range fm.filterMemMap[rID] {
					if hasName(inj) {
						continue
					}
					expr, err := parser.ParseExpr(s)
					if err != nil {
						return nil, err
					}
					if err = parser.Walk(inspector(injectLabels(inj)), expr, nil); err != nil {
						return nil, err
					}
					subqueries = append(subqueries, expr.String())
				}
				filteredQueries = append(filteredQueries, subqueries...)
				continue
			}
		}

		// if match or inject only then ok
		filteredQueries = append(filteredQueries, s)
	}

	return filteredQueries, nil

}

type inspector func(parser.Node, []parser.Node) error

func (f inspector) Visit(node parser.Node, path []parser.Node) (parser.Visitor, error) {
	if err := f(node, path); err != nil {
		return nil, err
	}
	return f, nil
}

func checkLabels(matchMemSet [][]*labels.Matcher) func(node parser.Node, path []parser.Node) error {
	return func(node parser.Node, path []parser.Node) error {
		switch n := node.(type) {
		case *parser.VectorSelector:
			for _, mm := range matchMemSet {
				if matchIntersection(n.LabelMatchers, mm) {
					return nil
				}
			}
			return fmt.Errorf("not match %v", matchMemSet)
		case *parser.MatrixSelector:
			for _, mm := range matchMemSet {
				if matchIntersection(n.VectorSelector.(*parser.VectorSelector).LabelMatchers, mm) {
					return nil
				}
			}
			return fmt.Errorf("not match %v", matchMemSet)
		}
		return nil
	}
}

func injectLabels(injectMemSet []*labels.Matcher) func(node parser.Node, path []parser.Node) error {
	return func(node parser.Node, path []parser.Node) error {
		switch n := node.(type) {
		case *parser.VectorSelector:
			n.LabelMatchers = append(n.LabelMatchers, injectMemSet...)
		case *parser.MatrixSelector:
			n.VectorSelector.(*parser.VectorSelector).LabelMatchers = append(n.VectorSelector.(*parser.VectorSelector).LabelMatchers, injectMemSet...)
		}
		return nil
	}
}

func hasName(injects []*labels.Matcher) bool {
	for _, inj := range injects {
		if inj.Name == "__name__" {
			return true
		}
	}
	return false
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
	if mri.Name == mmi.Name {
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
			return mri.Type == mmi.Type && mri.Value == mmi.Value
		}
	}
	return false
}
