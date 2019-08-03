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

// MatcherSet is a union of match[]
type matcherSet [][]*labels.Matcher

// doesn't work. I'm stupid :(
func (ms *matcherSet) String() string {
	return fmt.Sprintf("%v", [][]*labels.Matcher(*ms))
}

// Manager describe one filter map (client id: filters)
type Manager struct {
	idHeaderName string
	matchMemMap  map[string]matcherSet
	logger       kitlog.Logger
	mtx          sync.RWMutex
}

// NewManager creates new instance
func NewManager(l *kitlog.Logger) *Manager {
	fm := &Manager{
		idHeaderName: "",
		matchMemMap:  make(map[string]matcherSet),
		logger:       *l,
	}
	return fm
}

// ApplyConfig apply new config
func (fm *Manager) ApplyConfig(idHeaderName string, matchMap map[string][]string) error {
	fm.mtx.Lock()
	defer fm.mtx.Unlock()

	matchMemMap := make(map[string]matcherSet)
	var matcherSets [][]*labels.Matcher

	for id, matches := range matchMap {
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
	fm.idHeaderName = idHeaderName
	return nil
}

// FilterMatches main function
func (fm *Manager) FilterMatches(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		rID := r.Header.Get(fm.idHeaderName)
		if rID == "" {
			http.Error(w, fmt.Sprintf("ERROR: Empty header %v", fm.idHeaderName), http.StatusBadRequest)
			level.Warn(fm.logger).Log("msg", "empty header in filter request", "value", fm.idHeaderName)
			return
		}

		// prometheus/web/federate.go part :)
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("ERROR: error parsing form values: %v", err), http.StatusBadRequest)
			level.Warn(fm.logger).Log("msg", "cannot parse form values", "id", rID, "err", err)
			return
		}

		var rMatcherSets [][]*labels.Matcher
		level.Debug(fm.logger).Log("msg", "request match[] sets", "id", rID, "value", fmt.Sprintf("%v", r.Form["match[]"]))
		for _, s := range r.Form["match[]"] {
			matchers, err := promql.ParseMetricSelector(s)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				level.Warn(fm.logger).Log("msg", "cannot parse match[] sets", "id", rID, "value", s, "err", err)
				return
			}
			rMatcherSets = append(rMatcherSets, matchers)
		}

		// clean form
		r.Form.Del("match[]")

		// compare matcherSets with white list

		for _, mr := range rMatcherSets {
			for _, mm := range fm.matchMemMap[rID] {
				if matchIntersection(mr, mm) {
					r.Form.Add("match[]", toParam(mr))
					break
				}
			}
		}

		if len(r.Form["match[]"]) == 0 {
			http.Error(w, fmt.Sprintf("Wrong matches. You should use one of these sets %v", fm.matchMemMap[rID]), http.StatusForbidden)
			level.Warn(fm.logger).Log("msg", "filter result is empty", "id", rID, "value", fmt.Sprintf("%v", rMatcherSets))
			return
		}

		h.ServeHTTP(w, r)
	})
}

func matchIntersection(mr, mm []*labels.Matcher) bool {
	count := 0

	for _, mri := range mr {
		for _, mmi := range mm {
			if suitMatchers(mri, mmi) {
				count = count + 1
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

func toParam(mr []*labels.Matcher) string {
	str := "{"
	for _, mri := range mr {
		str = str + mri.String() + ","
	}
	return str + "}"
}
