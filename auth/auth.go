package auth

import (
	"net/http"
	"strings"
	"sync"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// Manager describe set of auth maps (auth: id)
type Manager struct {
	authHeaderName   string            //Header name
	authMemHeaderSet []string          //client ids
	authMemBasicMap  map[string]string //base64(user:password):id
	authMemBearerMap map[string]string //token:id
	logger           kitlog.Logger
	mtx              sync.RWMutex
}

// NewManager creates new instance
func NewManager(l *kitlog.Logger) *Manager {
	am := &Manager{
		authHeaderName:   "",
		authMemHeaderSet: make([]string, 0),
		authMemBasicMap:  make(map[string]string),
		authMemBearerMap: make(map[string]string),
		logger:           *l,
	}
	return am
}

// ApplyConfig apply new config
func (am *Manager) ApplyConfig(
	authHeaderName string,
	authMemHeaderSet []string,
	authMemBasicMap map[string]string,
	authMemBearerMap map[string]string) error {

	am.mtx.Lock()
	defer am.mtx.Unlock()

	am.authHeaderName = authHeaderName
	am.authMemHeaderSet = authMemHeaderSet
	am.authMemBasicMap = authMemBasicMap
	am.authMemBearerMap = authMemBearerMap

	return nil
}

// CopyConfig apply new config from another manager
func (am *Manager) CopyConfig(manager *Manager) error {
	am.mtx.Lock()
	defer am.mtx.Unlock()

	am.authHeaderName = manager.authHeaderName
	am.authMemHeaderSet = manager.authMemHeaderSet
	am.authMemBasicMap = manager.authMemBasicMap
	am.authMemBearerMap = manager.authMemBearerMap

	return nil
}

// CheckAuth try to check headers
func (am *Manager) CheckAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check header
		if header := r.Header.Get(am.authHeaderName); header != "" {
			for i := range am.authMemHeaderSet {
				if am.authMemHeaderSet[i] == header {
					level.Debug(am.logger).Log("msg", "found header", "id", header)
					h.ServeHTTP(w, r)
					return
				}
			}
		}
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			level.Debug(am.logger).Log("msg", "Incorrect Authorization header", "value", auth)
			return
		} else if strings.EqualFold(auth[:6], "Basic ") {
			level.Debug(am.logger).Log("msg", "found Basic Authorizatoin header")
			am.basicAuthInMem(h).ServeHTTP(w, r)
			return
		} else if strings.EqualFold(auth[:7], "Bearer ") {
			level.Debug(am.logger).Log("msg", "found Bearer Authorizatoin header")
			am.bearerAuthInMem(h).ServeHTTP(w, r)
			return
		} else {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			level.Debug(am.logger).Log("msg", "Incorrect Authorization header value", "value", auth)
			return
		}
	})
}

func (am *Manager) basicAuthInMem(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Basic "
		if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			level.Debug(am.logger).Log("msg", "Incorrect Authorization header Basic value")
			return
		}
		if v, ok := am.authMemBasicMap[auth[6:]]; ok {
			r.Header.Set(am.authHeaderName, v)
			level.Debug(am.logger).Log("msg", "correct Basic auth", "id", v)
		} else {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			level.Warn(am.logger).Log("msg", "unauthorized Basic")
			return
		}

		h.ServeHTTP(w, r)
	})
}

func (am *Manager) bearerAuthInMem(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			level.Debug(am.logger).Log("msg", "Incorrect Authorization header Bearer token value")
			return
		}
		if v, ok := am.authMemBearerMap[auth[7:]]; ok {
			r.Header.Set(am.authHeaderName, v)
			level.Debug(am.logger).Log("msg", "correct Bearer auth", "id", v)
		} else {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			level.Warn(am.logger).Log("msg", "unauthorized Bearer")
			return
		}
		h.ServeHTTP(w, r)
	})
}
