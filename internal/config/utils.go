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

func ExtractFilterMap(cfg *Config) (map[string][]string, error) {

	matchMap := make(map[string][]string)
	for id, c := range cfg.Clients {
		matchMap[string(id)] = c.Match
	}

	return matchMap, nil
}
