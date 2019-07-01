package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql"
)

// type MatchSet struct {
// 	ID         string `yaml:"id"`
// 	MatcherSet [][]*labels.Matcher
// 	// Match []string `yaml:", inline"`
// }
type MatcherSet [][]*labels.Matcher

var matchMemSet map[string]MatcherSet
var idHeaderName string //Header name

func SetMatchMemHeaderName(s string) {
	idHeaderName = s
}

func AddMemMatcherSets(id string, stringset []string) error {
	var matcherSets [][]*labels.Matcher
	for _, s := range stringset {
		matchers, err := promql.ParseMetricSelector(s)
		if err != nil {
			return err
		}
		matcherSets = append(matcherSets, matchers)
	}
	// matchMemSet = append(matchMemSet, MatchSet{
	// 	id,
	// 	matcherSets,
	// })

	matchMemSet[id] = matcherSets
	return nil
}

func FilterMatches(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// prometheus/web/federate.go part :)
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("ERROR: error parsing form values: %v", err), http.StatusBadRequest)
			return
		}

		rId := r.Header.Get(idHeaderName)
		if rId == "" {
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

		log.Printf("DEBUG: request matchset : %v\n", rMatcherSets)
		log.Printf("DEBUG: compared matchset : %v\n", matchMemSet[rId])

		// if len(rMatcherSets) < len(matchMemSet[rId]) {
		// 	http.Error(w, fmt.Sprintf("Not enough matches. You should use one of these sets: %v",
		// 		matchMemSet[rId]), http.StatusForbidden)
		// 	return
		// }

		for _, mr := range rMatcherSets {
			for _, mm := range matchMemSet[rId] {
				if containAll(mr, mm) {
					log.Printf("DEBUG: found equal : %v\n", toParam(mr))
					r.Form.Add("match[]", toParam(mr))
					break
				}
			}
		}

		if len(r.Form["match[]"]) == 0 {
			http.Error(w, fmt.Sprintf("Wrong matches. You should use one of these sets %v", matchMemSet[rId]), http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func containAll(mr, mm []*labels.Matcher) bool {
	count := 0

	for _, mri := range mr {
		for _, mmi := range mm {
			if equalMatchers(mri, mmi) {
				count = count + 1
			}
			if count == len(mm) {
				return true
			}
		}
	}
	return false
}

func equalMatchers(mri, mmi *labels.Matcher) bool {
	if mri.Name == mmi.Name &&
		mri.Type == mmi.Type &&
		mri.Value == mmi.Value {
		return true
	}
	return false
}

func toParam(mr []*labels.Matcher) string {
	str := "{"
	for _, mri := range mr {
		str = str + mri.String() + ","
	}
	return str + "}"
}
