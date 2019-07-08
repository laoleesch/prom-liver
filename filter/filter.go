package filter

import (
	"fmt"
	"net/http"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"
)

// MatcherSet is a union of match[]
type matcherSet [][]*labels.Matcher

func (ms *matcherSet) toString() string {
	return fmt.Sprintf("%v", ms)
}

// Manager describe one filter map (client id: filters)
type Manager struct {
	idHeaderName string
	matchMemSet  map[string]matcherSet
	logger       kitlog.Logger
}

// NewManager creates new instance
func NewManager(l *kitlog.Logger) *Manager {
	fm := &Manager{
		idHeaderName: "",
		matchMemSet:  make(map[string]matcherSet),
		logger:       *l,
	}
	return fm
}

// SetMatchMemHeaderName is like a setter
func (fm *Manager) SetMatchMemHeaderName(s string) {
	fm.idHeaderName = s
	level.Debug(fm.logger).Log("match.header", fm.idHeaderName)
}

// AddMatchMemSet adds a new id:matchset
func (fm *Manager) AddMatchMemSet(id string, stringset []string) error {
	var matcherSets [][]*labels.Matcher
	for _, s := range stringset {
		matchers, err := promql.ParseMetricSelector(s)
		if err != nil {
			return err
		}
		matcherSets = append(matcherSets, matchers)
	}
	fm.matchMemSet[id] = matcherSets
	level.Info(fm.logger).Log("client.id", id, "matchset", fmt.Sprintf("%v", fm.matchMemSet[id]))
	return nil
}

// FilterMatches main function
func (fm *Manager) FilterMatches(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// prometheus/web/federate.go part :)
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("ERROR: error parsing form values: %v", err), http.StatusBadRequest)
			level.Warn(fm.logger).Log("msg", "cannot parse form values", "err", err)
			return
		}

		rID := r.Header.Get(fm.idHeaderName)
		if rID == "" {
			http.Error(w, fmt.Sprintf("ERROR: Empty header %v", fm.idHeaderName), http.StatusBadRequest)
			level.Warn(fm.logger).Log("msg", "empty header in filter request", "value", fm.idHeaderName)
			return
		}

		var rMatcherSets [][]*labels.Matcher
		level.Debug(fm.logger).Log("msg", "request match[] sets", "value", r.Form["match[]"])
		for _, s := range r.Form["match[]"] {
			matchers, err := promql.ParseMetricSelector(s)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				level.Warn(fm.logger).Log("msg", "cannot parse match[] sets", "value", s, "err", err)
				return
			}
			rMatcherSets = append(rMatcherSets, matchers)
		}

		// clean form
		r.Form.Del("match[]")

		// compare matcherSets with white list

		for _, mr := range rMatcherSets {
			for _, mm := range fm.matchMemSet[rID] {
				if matchIntersection(mr, mm) {
					r.Form.Add("match[]", toParam(mr))
					break
				}
			}
		}

		if len(r.Form["match[]"]) == 0 {
			http.Error(w, fmt.Sprintf("Wrong matches. You should use one of these sets %v", fm.matchMemSet[rID]), http.StatusForbidden)
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
	switch mri.Type.String() + mmi.Type.String() {
	case "==~":
		return mmi.Matches(mri.Value)
	case "=!~":
		return mmi.Matches(mri.Value)
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
