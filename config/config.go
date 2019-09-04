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
		Port: "8080",
		// URI:            "/federate",
		// URIPrefix:      "",
		Api:            true,
		Federate:       true,
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
	Port string `yaml:"port,omitempty"`
	// URI            string `yaml:"uri,omitempty"`
	// URIPrefix      string `yaml:"uri-prefix,omitempty"`
	Api            bool   `yaml:"api-enable,omitempty"`
	Federate       bool   `yaml:"federate-enable,omitempty"`
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
		return newCfg, errors.Wrapf(err, "cannot read config file")
	}
	err = yaml.UnmarshalStrict(file, &newCfg)
	if err != nil {
		return newCfg, errors.Wrapf(err, "cannot parse config file")
	}

	return newCfg, nil
}

func readClientsConfigFiles(patFiles []string, l *kitlog.Logger) (map[string]Client, error) {
	fileClients := make(map[string]Client)
	files, err := findFiles(patFiles)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot find files")
	}
	level.Debug(*l).Log("msg", "found client config files", "files", fmt.Sprint(files))

	for _, f := range files {
		file, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot read config file")
		}
		clients := make(Client)
		err = yaml.UnmarshalStrict(file, &clients)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot parse config file")
		}
		fileClients[f] = clients
	}

	return fileClients, nil
}

func readCredsFiles(patFiles []string, l *kitlog.Logger) ([]string, error) {
	filesContent := make([]string, 0)
	files, err := findFiles(patFiles)
	level.Debug(*l).Log("msg", "found credentials files", "cnt", len(files))
	if err != nil {
		return nil, errors.Wrapf(err, "cannot find files")
	}

	for _, f := range files {
		content, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot read file")
		}
		filesContent = append(filesContent, string(content))
	}

	return filesContent, nil
}

func findFiles(patFiles []string) (files []string, err error) {
	for _, p := range patFiles {
		fs, err := filepath.Glob(p)
		if err != nil {
			return nil, err
		}
		files = append(files, fs...)
	}
	return
}

// LoadConfig for apply new config
func LoadConfig(configFile string, l *kitlog.Logger) (Config, error) {
	newCfg, err := readConfigFile(configFile, l)
	if err != nil {
		return newCfg, err
	}

	// load client config files
	if len(newCfg.ClientsFiles) > 0 {
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
					return newCfg, err
				}
				newCfg.Clients[id] = conf
			}

		}
	}

	//check empty clients set :)
	if len(newCfg.Clients) == 0 {
		return newCfg, fmt.Errorf("The set of clients is empty. Are you sure?")
	}

	//read credentials from files and etc
	for id, clientConfig := range newCfg.Clients {
		// copy user-password to []Base64
		if clientConfig.Auth.Basic.User != "" && clientConfig.Auth.Basic.Password != "" {
			strb := []byte(clientConfig.Auth.Basic.User + ":" + clientConfig.Auth.Basic.Password)
			str := base64.StdEncoding.EncodeToString(strb)
			clientConfig.Auth.Basic.Base64 = append(clientConfig.Auth.Basic.Base64, str)
		}
		// read base64 files and copy to []Base64
		if len(clientConfig.Auth.Basic.Files) > 0 {
			base64, err := readCredsFiles(clientConfig.Auth.Basic.Files, l)
			if err != nil {
				return newCfg, err
			}
			clientConfig.Auth.Basic.Base64 = append(clientConfig.Auth.Basic.Base64, base64...)
		}
		// read tokens files and copy to []Tokens
		if len(clientConfig.Auth.Bearer.Files) > 0 {
			tokens, err := readCredsFiles(clientConfig.Auth.Bearer.Files, l)
			if err != nil {
				return newCfg, err
			}
			clientConfig.Auth.Bearer.Tokens = append(clientConfig.Auth.Bearer.Tokens, tokens...)
		}
		newCfg.Clients[id] = clientConfig
	}

	return newCfg, err
}
