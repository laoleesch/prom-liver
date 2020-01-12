package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
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

	if err := validateConfig(authMemMap); err != nil {
		return errors.Wrapf(err, "error apply auth config ")
	}

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

// CheckAuth try to check auth headers and set authHeaderName header
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
			level.Debug(am.logger).Log("msg", "Empty or incorrect auth header")
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

func validateConfig(authMemMap map[int]map[string]string) error {
	for aType, conf := range authMemMap {
		switch aType {
		case TBasic:
			creds := make(map[string]string, len(conf))
			for sBase64, id := range conf {
				data, err := base64.StdEncoding.DecodeString(sBase64)
				if err != nil {
					return errors.Wrapf(err, "error decode base64 id:%s ", id)
				}
				userpass := strings.SplitN(string(data), ":", 2)
				// TODO
				if len(userpass[0]) == 0 || len(userpass[1]) == 0 {
					return fmt.Errorf("wrong login or pass id:%s", id)
				}
				if oldID, ok := creds[userpass[0]]; ok {
					return fmt.Errorf("basic duplicate usernane id1:%s, id2:%s ", oldID, id)
				}
				creds[userpass[0]] = id
			}
		case TBearer:
			for sToken, id := range conf {
				// TODO
				if len(sToken) < 2 {
					return fmt.Errorf("wrong token id:%s", id)
				}
			}
		case THeader:
			for sHeader, id := range conf {
				// TODO
				if len(sHeader) == 0 {
					return fmt.Errorf("empty header id:%s", id)
				}
			}
		default:
			return fmt.Errorf("wrong auth type ")
		}
	}
	return nil
}
