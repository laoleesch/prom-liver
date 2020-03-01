package config

import (
	"encoding/base64"
	"fmt"

	"github.com/laoleesch/prom-liver/pkg/auth"
)

func ExtractAuthMap(cfg *Config) (map[int]map[string]string, error) {

	authMemMap := make(map[int]map[string]string)
	authMemMap[auth.THeader] = make(map[string]string)
	authMemMap[auth.TBasic] = make(map[string]string)
	authMemMap[auth.TBearer] = make(map[string]string)

	var authMemBasicMapClient map[string]string
	var authMemBearerMapClient map[string]string
	var err error

	for id, c := range cfg.Clients {

		// check if empty auth config when Server.Auth = true
		// i don't like this way, but..
		if c.Auth.String() == "" {
			err = fmt.Errorf("global Auth is enabled but no auth config for client id: %v", id)
			return nil, err
		}

		// Header id set for Auth-enabled-cases
		if c.Auth.Header {
			authMemMap[auth.THeader][string(id)] = "true"
		}
		// Basic base64-id map
		authMemBasicMapClient = make(map[string]string)
		// copy user-password to []Base64
		if c.Auth.Basic.User != "" && c.Auth.Basic.Password != "" {
			strb := []byte(c.Auth.Basic.User + ":" + c.Auth.Basic.Password)
			str := base64.StdEncoding.EncodeToString(strb)
			if oldID, ok := authMemMap[auth.TBasic][str]; ok {
				err = fmt.Errorf("duplicate basic login pass values: current ID=%v, new ID=%v", oldID, id)
				return nil, err
			}
			authMemMap[auth.TBasic][str] = string(id)
		}
		if len(c.Auth.Basic.Base64) > 0 {
			for _, b := range c.Auth.Basic.Base64 {
				//TODO: maybe there needs to decode base64 and check login, not whole encoded login-pass
				if oldID, ok := authMemMap[auth.TBasic][b]; ok {
					err = fmt.Errorf("duplicate basic base64 value: current ID=%v, new ID=%v", oldID, id)
					return nil, err
				}
				authMemBasicMapClient[b] = string(id)
			}
			for b := range authMemBasicMapClient {
				authMemMap[auth.TBasic][b] = authMemBasicMapClient[b]
			}
		}

		// Bearer token-id map
		authMemBearerMapClient = make(map[string]string)
		if len(c.Auth.Bearer.Tokens) > 0 {
			for _, t := range c.Auth.Bearer.Tokens {
				if oldID, ok := authMemMap[auth.TBearer][t]; ok {
					err = fmt.Errorf("duplicate bearer token value: current ID=%v, new ID=%v", oldID, id)
					return nil, err
				}
				authMemBearerMapClient[t] = string(id)
			}
			for t := range authMemBearerMapClient {
				authMemMap[auth.TBearer][t] = authMemBearerMapClient[t]
			}
		}
	}

	return authMemMap, nil
}

func ExtractFilterMap(cfg *Config) (matchMap map[string][]string, injectMap map[string]string, err error) {

	err = nil

	matchMap = make(map[string][]string)
	injectMap = make(map[string]string)
	for id, c := range cfg.Clients {
		if len(c.Match) == 0 && len(c.Inject) == 0 {
			err = fmt.Errorf("no match or filter config for client id: %v", id)
			return nil, nil, err
		}
		if len(c.Match) > 0 {
			matchMap[string(id)] = c.Match
		}
		if len(c.Inject) > 0 {
			injectMap[string(id)] = c.Inject
		}
	}
	return
}
