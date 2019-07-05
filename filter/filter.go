package filter

import (
	"fmt"
	"net/http"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"
)

// MatcherSet is a union of match[]
type MatcherSet [][]*labels.Matcher

var matchMemSet map[string]MatcherSet
var idHeaderName string //Header name

// SetMatchMemHeaderName is like a setter
func SetMatchMemHeaderName(s string) {
	idHeaderName = s
}

// AddMemMatcherSets setter
func AddMemMatcherSets(id string, stringset []string) error {
	var matcherSets [][]*labels.Matcher
	for _, s := range stringset {
		matchers, err := promql.ParseMetricSelector(s)
		if err != nil {
			return err
		}
		matcherSets = append(matcherSets, matchers)
	}
	matchMemSet[id] = matcherSets
	return nil
}

// FilterMatches main function
func FilterMatches(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// prometheus/web/federate.go part :)
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("ERROR: error parsing form values: %v", err), http.StatusBadRequest)
			return
		}

		rID := r.Header.Get(idHeaderName)
		if rID == "" {
			http.Error(w, fmt.Sprintf("ERROR: Empty header %v", idHeaderName), http.StatusBadRequest)
			return
		}

		var rMatcherSets [][]*labels.Matcher
		for _, s := range r.Form["match[]"] {
			matchers, err := promql.ParseMetricSelector(s)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			rMatcherSets = append(rMatcherSets, matchers)
		}

		// clean form
		r.Form.Del("match[]")

		// compare matcherSets with white list

		for _, mr := range rMatcherSets {
			for _, mm := range matchMemSet[rID] {
				if containAll(mr, mm) {
					r.Form.Add("match[]", toParam(mr))
					break
				}
			}
		}

		if len(r.Form["match[]"]) == 0 {
			http.Error(w, fmt.Sprintf("Wrong matches. You should use one of these sets %v", matchMemSet[rID]), http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func containAll(mr, mm []*labels.Matcher) bool {
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
	switch mri.Type.String() + " " + mmi.Type.String() {
	case "= =~":
		return mmi.Matches(mri.Value)
	case "= !~":
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
