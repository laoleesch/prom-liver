package config

import (
	"encoding/base64"
	"errors"
	"io/ioutil"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"gopkg.in/yaml.v2"
)

var (
	// DefaultConfig is the default top-level configuration.
	DefaultConfig = Config{
		Server: DefaultServerConfig,
	}

	// DefaultServerConfig is the default global configuration.
	DefaultServerConfig = ServerConfig{
		Port:           "8080",
		Proxy:          "http://localhost:9090/",
		Authentication: true,
		HeaderName:     "X-Prom-Liver-Id",
	}
)

// Config includes all config.yaml
type Config struct {
	Server  ServerConfig   `yaml:"server,omitempty"`
	Clients []ClientConfig `yaml:"clients"`
}

// ServerConfig includes only "server:" three
type ServerConfig struct {
	Port           string `yaml:"port,omitempty"`
	Proxy          string `yaml:"proxy,omitempty"`
	Authentication bool   `yaml:"authentication,omitempty"`
	HeaderName     string `yaml:"id-header,omitempty"`
}

//ClientConfig includes configuration for each client
type ClientConfig struct {
	ID    string     `yaml:"id"`
	Auth  AuthSchema `yaml:"auth"`
	Match []string   `yaml:"match"`
}

// AuthSchema describe all available auth schemes
type AuthSchema struct {
	Header bool             `yaml:"header,omitempty"` //header 'X-Prom-Liver-Id' value
	Basic  AuthSchemaBasic  `yaml:"basic,omitempty"`
	Bearer AuthSchemaBearer `yaml:"bearer,omitempty"`
}

// AuthSchemaBasic basic yaml
type AuthSchemaBasic struct {
	User     string   `yaml:"user,omitempty"`
	Password string   `yaml:"password,omitempty"`
	Base64   []string `yaml:"base64,omitempty"`
	Files    []string `yaml:"files,omitempty"`
}

// AuthSchemaBearer bearer yaml
type AuthSchemaBearer struct {
	Tokens []string `yaml:"tokens,omitempty"`
	Files  []string `yaml:"files,omitempty"`
}

func readConfigFile(configFile string, l *kitlog.Logger) (Config, error) {
	newCfg := DefaultConfig

	// read configfile
	file, err := ioutil.ReadFile(configFile)
	if err != nil {
		level.Error(*l).Log("msg", "cannot read config file", "err", err)
		return newCfg, err
	}
	err = yaml.UnmarshalStrict(file, &newCfg)
	if err != nil {
		level.Error(*l).Log("msg", "cannot parse config file", "err", err)
		// os.Exit(2)
	}

	return newCfg, err
}

// LoadConfig for apply new config
func LoadConfig(configFile string, l *kitlog.Logger) (Config, error) {
	newCfg, err := readConfigFile(configFile, l)

	//checks
	if newCfg.Server.HeaderName == "" {
		err = errors.New("empty Header name")
	}
	//TODO: check unique usernames and other auth credentials...

	return newCfg, err
}

// GetSet return slice of base64 credentials and len of this slice
func (s *AuthSchemaBasic) GetSet(l *kitlog.Logger) ([]string, int) {
	base64tokens := make([]string, 0)

	if len(s.Base64) > 0 {
		for _, b := range s.Base64 {
			base64tokens = append(base64tokens, b)
		}
	}

	// read user-password
	if s.User != "" && s.Password != "" {
		strb := []byte(s.User + ":" + s.Password)
		str := base64.StdEncoding.EncodeToString(strb)
		base64tokens = append(base64tokens, str)
	}

	//read basic files
	if len(s.Files) > 0 {
		for _, f := range s.Files {
			content, err := ioutil.ReadFile(f)
			if err != nil {
				level.Error(*l).Log("msg", "cannot read basic auth file", "err", err)
			}
			base64tokens = append(base64tokens, string(content))
		}
	}

	return base64tokens, len(base64tokens)
}

// GetSet return slice of bearer tokens and len of this slice
func (s *AuthSchemaBearer) GetSet(l *kitlog.Logger) ([]string, int) {
	bearerTokens := make([]string, 0)

	if len(s.Tokens) > 0 {
		for _, t := range s.Tokens {
			bearerTokens = append(bearerTokens, t)
		}
	}
	//read bearer files
	if len(s.Files) > 0 {
		for _, f := range s.Files {
			content, err := ioutil.ReadFile(f)
			if err != nil {
				level.Error(*l).Log("msg", "cannot read bearer auth file", "err", err)
			}
			bearerTokens = append(bearerTokens, string(content))
		}
	}

	return bearerTokens, len(bearerTokens)
}
