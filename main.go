package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"

	auth "github.com/laoleesch/prom-liver/auth"
	filter "github.com/laoleesch/prom-liver/filter"
)

// ServerConfig includes only "server:" three
type ServerConfig struct {
	Port           string `yaml:"port,omitempty"`
	Proxy          string `yaml:"proxy,omitempty"`
	Authentication bool   `yaml:"authentication,omitempty"`
	HeaderName     string `yaml:"auth-header,omitempty"`
}

//ClientConfig includes configuration for each client
type ClientConfig struct {
	ID    string          `yaml:"id"`
	Auth  auth.AuthSchema `yaml:"auth"`
	Match []string        `yaml:"match"`
}

var (
	err    error
	logger kitlog.Logger

	//Cfg default config
	Cfg = struct {
		ConfigFile string
		Loglevel   string
		Server     ServerConfig   `yaml:"server,omitempty"`
		Clients    []ClientConfig `yaml:"clients"`
	}{
		Server: ServerConfig{
			Port:           "8080",
			Proxy:          "http://localhost:9090/",
			Authentication: true,
			HeaderName:     "X-Prom-Liver-Id",
		},
	}
)

func main() {

	c := kingpin.New(filepath.Base(os.Args[0]), "Auth-filter-reverse-proxy-server for Prometheus federate")
	c.HelpFlag.Short('h')

	// get configfile
	c.Flag("config", "Configuration file").Short('c').Default("config.yaml").StringVar(&Cfg.ConfigFile)
	c.Flag("loglevel", "Log level: debug, info, warning, error").Default("info").Short('l').StringVar(&Cfg.Loglevel)
	_, err := c.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, errors.Wrapf(err, "Error parsing commandline arguments"))
		c.Usage(os.Args[1:])
		os.Exit(2)
	}

	// init logger
	logger = kitlog.NewLogfmtLogger(kitlog.NewSyncWriter(os.Stderr))
	logger = kitlog.With(logger, "ts", kitlog.DefaultTimestamp)
	stdlog.SetOutput(kitlog.NewStdlibAdapter(logger))
	logger = setLoggerLevel(Cfg.Loglevel)
	level.Info(logger).Log("loglevel", Cfg.Loglevel)

	// read configfile
	file, err := ioutil.ReadFile(Cfg.ConfigFile)
	if err != nil {
		level.Error(logger).Log("msg", "cannot read config file", "err", err)
		os.Exit(2)
	}
	err = yaml.UnmarshalStrict(file, &Cfg)
	if err != nil {
		level.Error(logger).Log("msg", "cannot parse config file", "err", err)
		os.Exit(2)
	}
	level.Info(logger).Log("configfile", Cfg.ConfigFile)
	level.Info(logger).Log("server.port", Cfg.Server.Port)
	level.Info(logger).Log("server.proxy", Cfg.Server.Proxy)
	level.Info(logger).Log("server.authentication", Cfg.Server.Authentication)
	level.Info(logger).Log("server.auth-header", Cfg.Server.HeaderName)

	// set inMem auth maps from config
	auth.SetAuthMemHeaderName(Cfg.Server.HeaderName)
	if Cfg.Server.Authentication {
		authMemBasicMap := make(map[string]string)
		authMemBearerMap := make(map[string]string)
		var authMemHeaderSet []string
		for _, c := range Cfg.Clients {
			// Header id set for Auth-enabled-cases
			if c.Auth.Header {
				authMemHeaderSet = append(authMemHeaderSet, c.ID)
				level.Info(logger).Log("client.id", c.ID, "auth", "header")
			}
			// Basic base64-id map
			if c.Auth.Basic.User != "" && c.Auth.Basic.Password != "" {
				strb := []byte(c.Auth.Basic.User + ":" + c.Auth.Basic.Password)
				str := base64.StdEncoding.EncodeToString(strb)
				authMemBasicMap[str] = c.ID
				level.Info(logger).Log("client.id", c.ID, "auth", "basic")
			}
			// Bearer token-id map
			if c.Auth.Bearer.Token != "" {
				authMemBearerMap[c.Auth.Bearer.Token] = c.ID
				level.Info(logger).Log("client.id", c.ID, "auth", "bearer")
			}
		}
		auth.SetAuthMemHeaderSet(authMemHeaderSet)
		auth.SetAuthMemBasicMap(authMemBasicMap)
		auth.SetAuthMemBearerMap(authMemBearerMap)
	}

	// set inMem matcher sets from config
	filter.SetMatchMemHeaderName(Cfg.Server.HeaderName)
	for _, c := range Cfg.Clients {
		//TODO!!! BUG
		filter.AddMemMatcherSets(c.ID, c.Match)
		level.Info(logger).Log("client.id", c.ID, "matchset", strings.Join(c.Match, ", "))
	}

	if Cfg.Server.Authentication {
		http.Handle("/federate", handleGet(
			auth.CheckAuth(
				filter.FilterMatches(
					serveReverseProxy(Cfg.Server.Proxy)))))
	} else {
		http.Handle("/federate", handleGet(
			filter.FilterMatches(
				serveReverseProxy(Cfg.Server.Proxy))))
	}

	if err := http.ListenAndServe(":"+Cfg.Server.Port, nil); err != nil {
		level.Error(logger).Log("msg", "cannot start http listener", "err", err)
		os.Exit(2)
	}
}

func setLoggerLevel(s string) kitlog.Logger {
	switch strings.ToLower(s) {
	case "debug":
		logger = kitlog.With(logger, "caller", kitlog.DefaultCaller)
		logger = level.NewFilter(logger, level.AllowDebug())
	case "info":
		logger = level.NewFilter(logger, level.AllowInfo())
	case "warning":
		logger = level.NewFilter(logger, level.AllowWarn())
	case "error":
		logger = level.NewFilter(logger, level.AllowError())
	default:
		level.Error(logger).Log("msg", "wrong log level name", "value", Cfg.Loglevel)
		Cfg.Loglevel = "info"
		logger = level.NewFilter(logger, level.AllowInfo())
	}
	return logger
}

// filter non-GET requests
func handleGet(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// reverse proxy
func serveReverseProxy(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url, _ := url.Parse(target)
		proxy := httputil.NewSingleHostReverseProxy(url)

		// proxy.ErrorLog = logger

		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = url.Host

		if Cfg.Loglevel == "debug" {
			level.Debug(logger).Log("msg", "out request", "dump", requestDump(r))
		}

		proxy.ServeHTTP(w, r)
	})
}

// for debug :)
func requestDump(r *http.Request) []byte {
	requestDump, err := httputil.DumpRequest(r, true)
	logger.Log("sadasdasd")
	if err != nil {
		level.Debug(logger).Log("msg", "cannot make a request dump", "err", err)
	}
	return requestDump
}
