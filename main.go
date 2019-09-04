package main

import (

	// _ "net/http/pprof"

	"fmt"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/gorilla/mux"
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
		level.Error(logger).Log("msg", "Error load config", "err", err)
		os.Exit(2)
	}

	level.Info(logger).Log("server.port", Cfg.Server.Port)
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

	// config reload handler
	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)

		for {
			<-hup
			if err := reloadConfig(cmdConfigFile, &logger, amp, fmp); err != nil {
				level.Error(logger).Log("msg", "Error reloading config", "err", err)
			} else {
				level.Info(logger).Log("msg", "Config has been successfuly reloaded", "file", cmdConfigFile)
			}
		}
	}()

	// run handlers
	r := mux.NewRouter()
	r = r.Methods("GET").Subrouter()
	if Cfg.Server.Authentication {
		r.Use(amp.CheckAuth)
	}
	// r.Use(fmp.FilterMatches)

	r.Handle("/federate", fmp.FilterFederate(serveReverseProxy(Cfg.Server.Proxy))).Methods("GET")
	r.Handle("/api/v1/query", serveReverseProxy(Cfg.Server.Proxy)).Methods("GET")

	if err = r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		methods, err := route.GetMethods()
		pathTemplate, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		level.Info(logger).Log("server.uri", pathTemplate, "server.uri.methods", fmt.Sprint(methods))
		return nil
	}); err != nil {
		level.Error(logger).Log("msg", "Error while getting all routes", "err", err)
	}

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:" + Cfg.Server.Port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
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

	for id, c := range cfg.Clients {
		// Header id set for Auth-enabled-cases
		if c.Auth.Header {
			authMemMap[auth.THeader][string(id)] = "true"
			level.Debug(logger).Log("client.id", string(id), "auth", "header")
		}
		// Basic base64-id map
		authMemBasicMapClient = make(map[string]string)
		if len(c.Auth.Basic.Base64) > 0 {
			for _, b := range c.Auth.Basic.Base64 {
				//TODO: maybe there needs to decode base64 and check login, not whole encoded login-pass
				if newid, ok := authMemMap[auth.TBasic][b]; ok {
					err = fmt.Errorf("Duplicate basic base64 value: current ID=%v, new ID=%v", id, string(newid))
					return nil, err
				}
				authMemBasicMapClient[b] = string(id)
			}
			for b := range authMemBasicMapClient {
				authMemMap[auth.TBasic][b] = authMemBasicMapClient[b]
			}
			level.Debug(logger).Log("client.id", string(id), "auth", "basic", "credentials", len(authMemBasicMapClient))
		}

		// Bearer token-id map
		authMemBearerMapClient = make(map[string]string)
		if len(c.Auth.Bearer.Tokens) > 0 {
			for _, t := range c.Auth.Bearer.Tokens {
				if newid, ok := authMemMap[auth.TBearer][t]; ok {
					err = fmt.Errorf("Duplicate bearer token value: current ID=%v, new ID=%v", id, string(newid))
					return nil, err
				}
				authMemBearerMapClient[t] = string(id)
			}
			for t := range authMemBearerMapClient {
				authMemMap[auth.TBearer][t] = authMemBearerMapClient[t]
			}
			level.Debug(logger).Log("client.id", string(id), "auth", "bearer", "tokens", len(authMemBearerMapClient))
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
	for id, c := range cfg.Clients {
		matchMap[string(id)] = c.Match
	}
	err := newFilter.ApplyConfig(cfg.Server.HeaderName, matchMap)
	if err != nil {
		return nil, err
	}

	return newFilter, nil
}

func reloadConfig(filename string, l *kitlog.Logger, am *auth.Manager, fm *filter.Manager) error {
	cfg, err := config.LoadConfig(filename, &logger)
	if err != nil {
		return err
	}

	newAmp := auth.NewManager(&logger)
	if cfg.Server.Authentication {
		newAmp, err = configureAuth(&cfg)
		if err != nil {
			level.Error(logger).Log("msg", "cannot init new auth config", "err", err)
			return err
		}
	}

	newFmp := filter.NewManager(&logger)
	newFmp, err = configureFilter(&cfg)
	if err != nil {
		level.Error(logger).Log("msg", "cannot init new filter config", "err", err)
		return err
	}

	am.CopyConfig(newAmp)
	fm.CopyConfig(newFmp)

	return nil
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
		r.RequestURI = url.EscapedPath() + r.RequestURI

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
