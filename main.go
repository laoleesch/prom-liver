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
	err    error
	logger kitlog.Logger

	// cmd args
	cmdConfigFile string
	cmdLogLevel   string

	//Cfg default config
	Cfg = config.DefaultConfig

	// Auth & Match sets
	am auth.Manager
	fm filter.Manager
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
	logger = kitlog.NewLogfmtLogger(kitlog.NewSyncWriter(os.Stderr))
	logger = kitlog.With(logger, "ts", kitlog.DefaultTimestamp)
	stdlog.SetOutput(kitlog.NewStdlibAdapter(logger))
	logger = setLoggerLevel(cmdLogLevel, &logger)
	level.Info(logger).Log("loglevel", cmdLogLevel)
	level.Info(logger).Log("configfile", cmdConfigFile)

	// check configfile
	// f, err := os.Open(cmdConfigFile)
	// if err != nil {
	// 	level.Error(logger).Log("msg", "cannot open config file", "err", err)
	// 	os.Exit(2)
	// }
	// f.Close()

	// init auth and filter managers and load config
	// if err = reloadConfig(cmdConfigFile, &logger, newCfg); err != nil {
	// 	level.Error(logger).Log("msg", "Error loading config", "err", err)
	// 	// os.Exit(2)
	// }

	Cfg, err = config.LoadConfig(cmdConfigFile, &logger)
	if err != nil {
		os.Exit(2)
	}

	level.Info(logger).Log("server.port", Cfg.Server.Port)
	level.Info(logger).Log("server.proxy", Cfg.Server.Proxy)
	level.Info(logger).Log("server.authentication", Cfg.Server.Authentication)
	level.Info(logger).Log("server.id-header", Cfg.Server.HeaderName)

	am := auth.NewManager(&logger)
	fm := filter.NewManager(&logger)

	// set inMem auth maps from config
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
			if basicSet, cnt := c.Auth.Basic.GetSet(&logger); cnt > 0 {
				for _, b := range basicSet {
					authMemBasicMap[b] = c.ID
				}
				level.Info(logger).Log("client.id", c.ID, "auth", "basic", "credentials", cnt)
			}
			// Bearer token-id map
			if bearerSet, cnt := c.Auth.Bearer.GetSet(&logger); cnt > 0 {
				for _, t := range bearerSet {
					authMemBearerMap[t] = c.ID
				}
				level.Info(logger).Log("client.id", c.ID, "auth", "bearer", "tokens", cnt)
			}
		}
		am.ApplyConfig(Cfg.Server.HeaderName, authMemHeaderSet, authMemBasicMap, authMemBearerMap)
	}

	// set inMem matcher sets from config
	matchMap := make(map[string][]string)
	for _, c := range Cfg.Clients {
		matchMap[c.ID] = c.Match
	}
	fm.ApplyConfig(Cfg.Server.HeaderName, matchMap)

	// run handlers
	if Cfg.Server.Authentication {
		http.Handle("/federate", handleGet(
			am.CheckAuth(
				fm.FilterMatches(
					serveReverseProxy(Cfg.Server.Proxy)))))
	} else {
		http.Handle("/federate", handleGet(
			fm.FilterMatches(
				serveReverseProxy(Cfg.Server.Proxy))))
	}

	if err := http.ListenAndServe(":"+Cfg.Server.Port, nil); err != nil {
		level.Error(logger).Log("msg", "cannot start http listener", "err", err)
		os.Exit(2)
	}
}

func setLoggerLevel(s string, l *kitlog.Logger) kitlog.Logger {
	switch strings.ToLower(s) {
	case "debug":
		logger = level.NewFilter(*l, level.AllowDebug())
		logger = kitlog.With(logger, "caller", kitlog.DefaultCaller)
	case "info":
		logger = level.NewFilter(*l, level.AllowInfo())
	case "warning":
		logger = level.NewFilter(*l, level.AllowWarn())
	case "error":
		logger = level.NewFilter(*l, level.AllowError())
	default:
		level.Error(*l).Log("msg", "wrong log level name", "value", cmdLogLevel)
		cmdLogLevel = "info"
		logger = level.NewFilter(*l, level.AllowInfo())
	}
	return logger
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
