package main

import (
	"net/http"
	"strings"
)

// var authMemHeaderMap map[string]string //base64(header:value):id
var authMemBasicMap map[string]string  //base64(user:password):id
var authMemBearerMap map[string]string //token:id

// func SetMemHeaderMap(m map[string]string) {
// 	authMemHeaderMap = m
// }

func SetMemBasicMap(m map[string]string) {
	authMemBasicMap = m
}

func SetMemBearerMap(m map[string]string) {
	authMemBearerMap = m
}

func CheckAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.EqualFold(auth[:6], "Basic ") {
			h = basicAuthInMem(h)
		} else if strings.EqualFold(auth[:7], "Bearer ") {
			h = bearerAuthInMem(h)
		} else {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func basicAuthInMem(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Basic "
		if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
			return
		}
		if v, ok := authMemBasicMap[auth[:6]]; ok {
			r.Header.Set("X-Prom-Liver-Id", v)
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			// w.Header().Set("X-Prom-Liver-Id", "none")
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func bearerAuthInMem(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
			return
		}
		if v, ok := authMemBearerMap[auth[:7]]; ok {
			r.Header.Set("X-Prom-Liver-Id", v)
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="Restricted"`)
			// w.Header().Set("X-Prom-Liver-Id", "none")
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)
	})
}
