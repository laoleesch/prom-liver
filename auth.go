package main

import (
	"net/http"
	"strings"
)

type AuthSchema struct {
	Header bool             `yaml:"header,omitempty"` //header 'X-Prom-Liver-Id' value
	Basic  AuthSchemaBasic  `yaml:"basic,omitempty"`
	Bearer AuthSchemaBearer `yaml:"bearer,omitempty"`
}

type AuthSchemaBasic struct {
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	// TODO: Base64   string `yaml:"base64,omitempty"`
	// TODO: File string `yaml:"file,omitempty"`
}

type AuthSchemaBearer struct {
	Token string `yaml:"token,omitempty"`
	// TODO: File  string `yaml:"file,omitempty"`
}

var authMemHeaderSet []string          //client ids
var authMemBasicMap map[string]string  //base64(user:password):id
var authMemBearerMap map[string]string //token:id

func SetMemHeaderSet(s []string) {
	authMemHeaderSet = s
}

func SetMemBasicMap(m map[string]string) {
	authMemBasicMap = m
}

func SetMemBearerMap(m map[string]string) {
	authMemBearerMap = m
}

func CheckAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if i,

		auth := r.Header.Get("Authorization")
		if len(auth) < 8 {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		} else if strings.EqualFold(auth[:6], "Basic ") {
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
		requestDump(r, "I'm in basicAuthInMem")
		const prefix = "Basic "
		if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		if v, ok := authMemBasicMap[auth[6:]]; ok {
			r.Header.Set("X-Prom-Liver-Id", v)
		} else {
			// w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
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
		requestDump(r, "I'm in bearerAuthInMem")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		if v, ok := authMemBearerMap[auth[7:]]; ok {
			r.Header.Set("X-Prom-Liver-Id", v)
		} else {
			// w.Header().Set("WWW-Authenticate", `Bearer realm="Restricted"`)
			// w.Header().Set("X-Prom-Liver-Id", "none")
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)
	})
}
