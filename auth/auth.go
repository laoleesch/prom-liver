package auth

import (
	"net/http"
	"strings"
	"sync"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// type of auth schema
const (
	TBasic = iota
	TBearer
	THeader
)

// Manager describe set of auth maps (auth: id)
type Manager struct {
	authHeaderName string                    //Header name
	authMemMap     map[int]map[string]string //map (type->map) of maps (base64->id, token->id, header_value->bool)
	logger         kitlog.Logger
	mtx            sync.RWMutex
}

// NewManager creates new instance
func NewManager(l *kitlog.Logger) *Manager {
	am := &Manager{
		authHeaderName: "",
		authMemMap:     make(map[int]map[string]string),
		logger:         *l,
	}
	return am
}

// ApplyConfig apply new config
func (am *Manager) ApplyConfig(
	authHeaderName string,
	authMemMap map[int]map[string]string) error {

	am.mtx.Lock()
	defer am.mtx.Unlock()

	am.authHeaderName = authHeaderName
	am.authMemMap = authMemMap

	return nil
}

// CopyConfig apply new config from another manager
func (am *Manager) CopyConfig(manager *Manager) error {
	am.mtx.Lock()
	defer am.mtx.Unlock()

	am.authHeaderName = manager.authHeaderName
	am.authMemMap = manager.authMemMap

	return nil
}

// CheckAuth try to check headers
func (am *Manager) CheckAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check header
		if header := r.Header.Get(am.authHeaderName); header != "" {
			if _, ok := am.authMemMap[THeader][header]; ok {
				level.Debug(am.logger).Log("msg", "found header", "id", header)
				h.ServeHTTP(w, r)
				return
			}
		}
		auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(auth) != 2 || auth[0] == "" {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		switch strings.ToLower(auth[0]) {
		case "basic":
			level.Debug(am.logger).Log("msg", "found Basic Authorizatoin header")
			am.basicAuthInMem(h).ServeHTTP(w, r)
		case "bearer":
			level.Debug(am.logger).Log("msg", "found Bearer Authorizatoin header")
			am.bearerAuthInMem(h).ServeHTTP(w, r)
		default:
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			level.Debug(am.logger).Log("msg", "Incorrect Authorization header value", "value", auth[0])
		}
	})
}

func (am *Manager) basicAuthInMem(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		// const prefix = "Basic "
		// if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		// 	http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		// 	level.Debug(am.logger).Log("msg", "Incorrect Authorization header Basic value")
		// 	return
		// }
		if v, ok := am.authMemMap[TBasic][auth[6:]]; ok {
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
		// const prefix = "Bearer "
		// if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		// 	http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		// 	level.Debug(am.logger).Log("msg", "Incorrect Authorization header Bearer token value")
		// 	return
		// }
		if v, ok := am.authMemMap[TBearer][auth[7:]]; ok {
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
