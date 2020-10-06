package config

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// Config includes all config.yaml
type Config struct {
	Web    WebConfig    `yaml:"web,omitempty"`
	Remote RemoteConfig `yaml:"remote,omitempty"`

	ClientsFiles []string `yaml:"clients_files,omitempty"`
	Clients      Clients  `yaml:"clients,omitempty"`
}

// WebConfig config
type WebConfig struct {
	Auth       bool   `yaml:"auth,omitempty"`
	HeaderName string `yaml:"header,omitempty"`
	Handlers   WebHandlersConfig
}

// WebHandlersConfig handlers configs
type WebHandlersConfig struct {
	API          bool `yaml:"api,omitempty"`
	Federate     bool `yaml:"federate,omitempty"`
	APIVMLabels  bool `yaml:"labels,omitempty"`
	ConfigReload bool `yaml:"config_reload,omitempty"`
}

// RemoteConfig includes configs for remote PromQL service
type RemoteConfig struct {
	URL  string           `yaml:"url,omitempty"`
	Auth RemoteAuthConfig `yaml:"auth,omitempty"`
	TLS  RemoteTLSConfig  `yaml:"tls,omitempty"`
}

// RemoteAuthConfig includes auth configs for remote PromQL service
type RemoteAuthConfig struct {
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	Token    string `yaml:"token,omitempty"`
}

func (c *RemoteAuthConfig) String() string {
	result := ""
	if c.Password != "" || c.User != "" {
		result = fmt.Sprintf("%s basic: true \n", result)
	}
	if c.Token != "" {
		result = fmt.Sprintf("%s bearer: true \n", result)
	}
	return result
}

// RemoteTLSConfig includes TLS configs for remote PromQL service
type RemoteTLSConfig struct {
	Verify bool `yaml:"verify,omitempty"`
}

//Clients includes configuration for each client
type Clients map[ClientID]ClientConfig

//ClientID is client id
type ClientID string

//ClientConfig client configuration
type ClientConfig struct {
	// ID    string     `yaml:"id"`
	Auth   AuthSchema `yaml:"auth,omitempty"`
	Match  []string   `yaml:"match,omitempty"`
	Inject string     `yaml:"inject,omitempty"`
	Filter []string   `yaml:"filter,omitempty"`
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

func (c *AuthSchema) String() string {
	result := ""

	if c.Header {
		result = fmt.Sprintf("%s header: true \n", result)
	}
	if c.Basic.User != "" && c.Basic.Password != "" {
		result = fmt.Sprintf("%s auth basic user password: true \n", result)
	}
	if len(c.Basic.Base64) > 0 {
		result = fmt.Sprintf("%s auth basic base64: %d \n", result, len(c.Basic.Base64))
	}
	if len(c.Bearer.Tokens) > 0 {
		result = fmt.Sprintf("%s auth bearer tokens: %d \n", result, len(c.Bearer.Tokens))
	}
	return result
}

// Manager controls config from file
type Manager struct {
	configFile string
	logger     kitlog.Logger
}

// New creates Manager
func New(cf string, l *kitlog.Logger) (*Manager, error) {
	if l == nil {
		return nil, fmt.Errorf("logger is nil")
	}
	if cf == "" {
		return nil, fmt.Errorf("filename is empty")
	}
	cm := &Manager{
		configFile: cf,
		logger:     *l,
	}
	return cm, nil
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		Web: WebConfig{
			Auth:       true,
			HeaderName: "X-Prom-Liver-Id",
			Handlers: WebHandlersConfig{
				API:          true,
				Federate:     true,
				APIVMLabels:  false,
				ConfigReload: true,
			},
		},
		Remote: RemoteConfig{
			Auth: RemoteAuthConfig{
				User:     "",
				Password: "",
				Token:    "",
			},
			TLS: RemoteTLSConfig{
				Verify: false,
			},
		},
	}
}

// LoadConfig returns Config after it reads and parse all config files
func (cm *Manager) LoadConfig() (newCfg Config, err error) {
	newCfg, err = cm.loadConfigFile()
	if err != nil {
		return newCfg, errors.Wrapf(err, "cannot load config file ")
	}

	if len(newCfg.ClientsFiles) > 0 {
		newCfg, err = cm.loadClientsConfigFiles(newCfg)
		if err != nil {
			return newCfg, errors.Wrapf(err, "cannot load clients config files ")
		}
	}

	if len(newCfg.Clients) == 0 {
		return newCfg, fmt.Errorf("the set of clients is empty. Are you sure?")
	}

	newCfg, err = cm.loadCredsFiles(newCfg)
	if err != nil {
		return newCfg, errors.Wrapf(err, "cannot load credentials files ")
	}

	return
}

func (cm *Manager) loadConfigFile() (newCfg Config, err error) {
	newCfg = DefaultConfig()
	level.Debug(cm.logger).Log("msg", "read file", "file", cm.configFile)
	file, err := ioutil.ReadFile(cm.configFile)
	if err != nil {
		return newCfg, errors.Wrapf(err, "cannot read config file")
	}
	err = yaml.UnmarshalStrict(file, &newCfg)
	if err != nil {
		return newCfg, errors.Wrapf(err, "cannot parse config file")
	}

	return
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

func (cm *Manager) loadClientsConfigFiles(newCfg Config) (Config, error) {
	level.Debug(cm.logger).Log("msg", "try to find clients config files", "patterns", fmt.Sprint(newCfg.ClientsFiles))
	files, err := findFiles(newCfg.ClientsFiles)
	if err != nil {
		return newCfg, errors.Wrapf(err, "error finding clients config files")
	}
	if len(files) == 0 {
		return newCfg, nil
	}

	level.Debug(cm.logger).Log("msg", "found client config files", "files", fmt.Sprint(files))
	for _, f := range files {
		level.Debug(cm.logger).Log("msg", "read file", "file", f)
		file, err := ioutil.ReadFile(f)
		if err != nil {
			return newCfg, errors.Wrapf(err, "cannot read client config file %v", f)
		}
		clients := make(Clients)
		err = yaml.UnmarshalStrict(file, &clients)
		if err != nil {
			return newCfg, errors.Wrapf(err, "cannot parse client config file %v", f)
		}
		for id, conf := range clients {
			if _, ok := newCfg.Clients[id]; ok {
				return newCfg, fmt.Errorf("duplicate client ID from files: ID=%v, file=%v", id, f)
			}
			newCfg.Clients[id] = conf
		}
	}

	return newCfg, nil
}

func (cm *Manager) loadCredsFiles(newCfg Config) (Config, error) {
	for id, clientConfig := range newCfg.Clients {
		// read base64 files and copy to []Base64
		if len(clientConfig.Auth.Basic.Files) > 0 {
			level.Debug(cm.logger).Log("msg", "try to find base64 creds files", "patterns", fmt.Sprint(clientConfig.Auth.Basic.Files))
			base64, err := cm.readCredsFiles(clientConfig.Auth.Basic.Files)
			if err != nil {
				return newCfg, err
			}
			clientConfig.Auth.Basic.Base64 = append(clientConfig.Auth.Basic.Base64, base64...)
		}
		// read tokens files and copy to []Tokens
		if len(clientConfig.Auth.Bearer.Files) > 0 {
			level.Debug(cm.logger).Log("msg", "try to find bearer creds files", "patterns", fmt.Sprint(clientConfig.Auth.Bearer.Files))
			tokens, err := cm.readCredsFiles(clientConfig.Auth.Bearer.Files)
			if err != nil {
				return newCfg, err
			}
			clientConfig.Auth.Bearer.Tokens = append(clientConfig.Auth.Bearer.Tokens, tokens...)
		}
		newCfg.Clients[id] = clientConfig
	}
	return newCfg, nil
}

func (cm *Manager) readCredsFiles(patFiles []string) ([]string, error) {
	filesContent := make([]string, 0)
	files, err := findFiles(patFiles)
	if err != nil {
		return nil, errors.Wrapf(err, "error finding creds files")
	}
	level.Debug(cm.logger).Log("msg", "found credentials files", "files", fmt.Sprint(files))
	for _, f := range files {
		level.Debug(cm.logger).Log("msg", "read file", "file", f)
		content, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot read file")
		}
		filesContent = append(filesContent, string(content))
	}

	return filesContent, nil
}
