package config

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
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
		URI:            "/federate",
		Proxy:          "http://localhost:9090/",
		Authentication: true,
		HeaderName:     "X-Prom-Liver-Id",
	}
)

// Config includes all config.yaml
type Config struct {
	Server       ServerConfig `yaml:"server,omitempty"`
	ClientsFiles []string     `yaml:"clients_files,omitempty"`
	Clients      Client       `yaml:"clients,omitempty"`
}

// ServerConfig includes only "server:" three
type ServerConfig struct {
	Port           string `yaml:"port,omitempty"`
	URI            string `yaml:"uri,omitempty"`
	Proxy          string `yaml:"proxy,omitempty"`
	Authentication bool   `yaml:"authentication,omitempty"`
	HeaderName     string `yaml:"id-header,omitempty"`
}

//Client includes configuration for each client
type Client map[ClientID]ClientConfig

//ClientID is client id
type ClientID string

//ClientConfig client configuration
type ClientConfig struct {
	// ID    string     `yaml:"id"`
	Auth  AuthSchema `yaml:"auth,omitempty"`
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
	level.Debug(*l).Log("msg", "try read config file", "file", configFile)

	// read configfile
	file, err := ioutil.ReadFile(configFile)
	if err != nil {
		level.Error(*l).Log("msg", "cannot read config file", "err", err)
		return newCfg, err
	}
	err = yaml.UnmarshalStrict(file, &newCfg)
	if err != nil {
		level.Error(*l).Log("msg", "cannot parse config file", "err", err)
		return newCfg, err
	}

	return newCfg, nil
}

func readClientsConfigFiles(patFiles []string, l *kitlog.Logger) (map[string]Client, error) {
	fileClients := make(map[string]Client)
	var files []string

	for _, p := range patFiles {
		fs, err := filepath.Glob(p)

		if err != nil || len(fs) == 0 {
			return nil, errors.Wrapf(err, "error retrieving rule files for %s", p)
		}
		files = append(files, fs...)
	}
	level.Debug(*l).Log("msg", "found client config files", "files", fmt.Sprint(files))

	for _, f := range files {
		file, err := ioutil.ReadFile(f)
		if err != nil {
			level.Error(*l).Log("msg", "cannot read config file", "err", err)
			return nil, err
		}
		clients := make(Client)
		err = yaml.UnmarshalStrict(file, &clients)
		if err != nil {
			level.Error(*l).Log("msg", "cannot parse config file", "err", err)
			return nil, err
		}
		fileClients[f] = clients
	}

	return fileClients, nil
}

// LoadConfig for apply new config
func LoadConfig(configFile string, l *kitlog.Logger) (Config, error) {
	newCfg, err := readConfigFile(configFile, l)
	if err != nil {
		return newCfg, err
	}

	// load client config files
	clientsFromFiles, err := readClientsConfigFiles(newCfg.ClientsFiles, l)
	if err != nil {
		return newCfg, err
	}
	level.Debug(*l).Log("msg", "found clients from files", "cnt", len(clientsFromFiles))
	for file, clients := range clientsFromFiles {
		level.Debug(*l).Log("msg", "read file", "file", file)
		for id, conf := range clients {
			if _, ok := newCfg.Clients[id]; ok {
				err = fmt.Errorf("Duplicate client ID from files: ID=%v, file=%v", id, file)
				level.Error(*l).Log("msg", "error add client from file", "err", err)
			} else {
				newCfg.Clients[id] = conf
			}
		}

	}

	//TODO: check unique usernames and other auth credentials...

	return newCfg, err
}

// GetAll return slice of base64 credentials and len of this slice
func (s *AuthSchemaBasic) GetAll(l *kitlog.Logger) ([]string, int) {
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

// GetAll return slice of bearer tokens and len of this slice
func (s *AuthSchemaBearer) GetAll(l *kitlog.Logger) ([]string, int) {
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
