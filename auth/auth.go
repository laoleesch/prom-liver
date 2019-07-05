package auth

import (
	"net/http"
	"strings"
)

// AuthSchema describe all available auth schemes
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
var authHeaderName string              //Header name
var authMemBasicMap map[string]string  //base64(user:password):id
var authMemBearerMap map[string]string //token:id

func SetAuthMemHeaderName(s string) {
	authHeaderName = s
}

func SetAuthMemHeaderSet(s []string) {
	authMemHeaderSet = s
}

func SetAuthMemBasicMap(m map[string]string) {
	authMemBasicMap = m
}

func SetAuthMemBearerMap(m map[string]string) {
	authMemBearerMap = m
}

func CheckAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check header
		if header := r.Header.Get(authHeaderName); header != "" {
			for i := range authMemHeaderSet {
				if authMemHeaderSet[i] == header {
					h.ServeHTTP(w, r)
					return
				}
			}
		}
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		} else if strings.EqualFold(auth[:6], "Basic ") {
			basicAuthInMem(h).ServeHTTP(w, r)
			return
		} else if strings.EqualFold(auth[:7], "Bearer ") {
			bearerAuthInMem(h).ServeHTTP(w, r)
			return
		} else {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
	})
}

func basicAuthInMem(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Basic "
		if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		if v, ok := authMemBasicMap[auth[6:]]; ok {
			r.Header.Set(authHeaderName, v)
		} else {
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
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		if v, ok := authMemBearerMap[auth[7:]]; ok {
			r.Header.Set(authHeaderName, v)
		} else {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}
