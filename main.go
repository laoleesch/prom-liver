package main

import (

	// _ "net/http/pprof"

	"fmt"
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

	auth "github.com/laoleesch/prom-liver/auth"
	config "github.com/laoleesch/prom-liver/config"
	filter "github.com/laoleesch/prom-liver/filter"
)

var (
	logger kitlog.Logger

	// cmd args
	cmdConfigFile string
	cmdLogLevel   string
)

func main() {

	c := kingpin.New(filepath.Base(os.Args[0]), "Auth-filter-reverse-proxy-server for Prometheus federate")
	c.HelpFlag.Short('h')
	c.Flag("loglevel", "Log level: debug, info, warning, error").Default("info").Short('l').StringVar(&cmdLogLevel)
	c.Flag("config", "Configuration file").Short('c').Default("config.yaml").StringVar(&cmdConfigFile)
	_, err := c.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, errors.Wrapf(err, "Error parsing commandline arguments"))
		c.Usage(os.Args[1:])
		os.Exit(2)
	}

	// init logger
	logger = initLogger(cmdLogLevel)
	level.Info(logger).Log("loglevel", cmdLogLevel)
	level.Info(logger).Log("configfile", cmdConfigFile)

	// Load config file
	Cfg := config.DefaultConfig
	Cfg, err = config.LoadConfig(cmdConfigFile, &logger)
	if err != nil {
		os.Exit(2)
	}

	level.Info(logger).Log("server.port", Cfg.Server.Port)
	level.Info(logger).Log("server.uri", Cfg.Server.Uri)
	level.Info(logger).Log("server.proxy", Cfg.Server.Proxy)
	level.Info(logger).Log("server.authentication", Cfg.Server.Authentication)
	level.Info(logger).Log("server.id-header", Cfg.Server.HeaderName)

	// apply config to managers
	amp := auth.NewManager(&logger)
	if Cfg.Server.Authentication {
		amp, err = configureAuth(&Cfg)
		if err != nil {
			level.Error(logger).Log("msg", "cannot init auth config", "err", err)
			os.Exit(2)
		}
	}

	fmp := filter.NewManager(&logger)
	fmp, err = configureFilter(&Cfg)
	if err != nil {
		level.Error(logger).Log("msg", "cannot init filter config", "err", err)
		os.Exit(2)
	}

	// run handlers
	if Cfg.Server.Authentication {
		http.Handle(Cfg.Server.Uri,
			handleGet(
				amp.CheckAuth(
					fmp.FilterMatches(
						serveReverseProxy(Cfg.Server.Proxy)))))
	} else {
		http.Handle(Cfg.Server.Uri,
			handleGet(
				fmp.FilterMatches(
					serveReverseProxy(Cfg.Server.Proxy))))
	}

	if err := http.ListenAndServe(":"+Cfg.Server.Port, nil); err != nil {
		level.Error(logger).Log("msg", "cannot start http listener", "err", err)
		os.Exit(2)
	}
}

func initLogger(s string) kitlog.Logger {
	logger = kitlog.NewLogfmtLogger(kitlog.NewSyncWriter(os.Stderr))
	logger = kitlog.With(logger, "ts", kitlog.DefaultTimestamp)
	stdlog.SetOutput(kitlog.NewStdlibAdapter(logger))
	switch strings.ToLower(s) {
	case "debug":
		logger = level.NewFilter(logger, level.AllowDebug())
		logger = kitlog.With(logger, "caller", kitlog.DefaultCaller)
	case "info":
		logger = level.NewFilter(logger, level.AllowInfo())
	case "warning":
		logger = level.NewFilter(logger, level.AllowWarn())
	case "error":
		logger = level.NewFilter(logger, level.AllowError())
	default:
		level.Error(logger).Log("msg", "wrong log level name", "value", cmdLogLevel)
		cmdLogLevel = "info"
		logger = level.NewFilter(logger, level.AllowInfo())
	}
	return logger
}

func configureAuth(cfg *config.Config) (*auth.Manager, error) {
	authMemMap := make(map[int]map[string]string)
	authMemMap[auth.THeader] = make(map[string]string)
	authMemMap[auth.TBasic] = make(map[string]string)
	authMemMap[auth.TBearer] = make(map[string]string)

	var authMemBasicMapClient map[string]string
	var authMemBearerMapClient map[string]string
	var err error

	level.Debug(logger).Log("msg", "prepearing auth config")

	for _, c := range cfg.Clients {
		// Header id set for Auth-enabled-cases
		if c.Auth.Header {
			authMemMap[auth.THeader][c.ID] = "true"
			level.Debug(logger).Log("client.id", c.ID, "auth", "header")
		}
		// Basic base64-id map
		authMemBasicMapClient = make(map[string]string)
		if basicList, cnt := c.Auth.Basic.GetAll(&logger); cnt > 0 {
			for _, b := range basicList {
				//maybe there needs to decode base64 and check login, not whole encoded login-pass
				if id, ok := authMemMap[auth.TBasic][b]; ok {
					err = fmt.Errorf("Duplicate basic base64 value: current ID=%v, new ID=%v", id, c.ID)
					return nil, err
				}
				authMemBasicMapClient[b] = c.ID
			}
			for b := range authMemBasicMapClient {
				authMemMap[auth.TBasic][b] = authMemBasicMapClient[b]
			}
			level.Debug(logger).Log("client.id", c.ID, "auth", "basic", "credentials", len(authMemBasicMapClient))
		}

		// Bearer token-id map
		authMemBearerMapClient = make(map[string]string)
		if bearerList, cnt := c.Auth.Bearer.GetAll(&logger); cnt > 0 {
			for _, t := range bearerList {
				if id, ok := authMemMap[auth.TBearer][t]; ok {
					err = fmt.Errorf("Duplicate bearer token value: current ID=%v, new ID=%v", id, c.ID)
					return nil, err
				}
				authMemBearerMapClient[t] = c.ID
			}
			for t := range authMemBearerMapClient {
				authMemMap[auth.TBearer][t] = authMemBearerMapClient[t]
			}
			level.Debug(logger).Log("client.id", c.ID, "auth", "bearer", "tokens", len(authMemBearerMapClient))
		}
	}
	newAuth := auth.NewManager(&logger)
	err = newAuth.ApplyConfig(cfg.Server.HeaderName, authMemMap)
	if err != nil {
		return nil, err
	}

	return newAuth, nil
}

func configureFilter(cfg *config.Config) (*filter.Manager, error) {
	newFilter := filter.NewManager(&logger)

	matchMap := make(map[string][]string)
	for _, c := range cfg.Clients {
		matchMap[c.ID] = c.Match
	}
	err := newFilter.ApplyConfig(cfg.Server.HeaderName, matchMap)
	if err != nil {
		return nil, err
	}

	return newFilter, nil
}

// func reloadConfig(filename string, l *kitlog.Logger, am *auth.Manager, fm *filter.Manager) error {

// 	return nil
// }

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

		if cmdLogLevel == "debug" {
			level.Debug(logger).Log("msg", "out request", "dump", requestDump(r))
		}

		proxy.ServeHTTP(w, r)
	})
}

// for debug :)
func requestDump(r *http.Request) []byte {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		level.Debug(logger).Log("msg", "cannot make a request dump", "err", err)
	}
	return requestDump
}
