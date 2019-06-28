package main

import "net/http"

type MatchSet struct {
	Match string `yaml:", inline"`
}

func FilterMatches(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// TODO

		h.ServeHTTP(w, r)
	})
}
