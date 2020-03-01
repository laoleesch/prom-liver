package main

import (

	// _ "net/http/pprof"

	"context"
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

	config "github.com/laoleesch/prom-liver/internal/config"
	auth "github.com/laoleesch/prom-liver/pkg/auth"
	filter "github.com/laoleesch/prom-liver/pkg/filter"
)

var (
	logger kitlog.Logger

	// cmd args
	cmdConfigFile string
	cmdLogLevel   string

	// gloabal config
	Cfg config.Config

	// reload config channel
	chHTTPReload chan chan error

	// managers
	cmp *config.ConfigManager
	amp *auth.Manager
	fmp *filter.Manager
)

func main() {

	c := kingpin.New(filepath.Base(os.Args[0]), "ACL for PromQL")
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

	// Init config
	Cfg = config.DefaultConfig
	amp = auth.NewManager(&logger)
	fmp = filter.NewManager(&logger)

	cmp, err = config.New(cmdConfigFile, &logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error init ConfigManager", "err", err)
		os.Exit(2)
	}

	err = reloadConfig(cmp)
	if err != nil {
		level.Error(logger).Log("msg", "Error load config", "err", err)
		os.Exit(2)
	}

	level.Info(logger).Log("server.port", Cfg.Server.Port)
	level.Info(logger).Log("server.proxy", Cfg.Server.Proxy)
	level.Info(logger).Log("server.authentication", Cfg.Server.Authentication)
	level.Info(logger).Log("server.id-header", Cfg.Server.HeaderName)

	// config reload handler
	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		chHTTPReload = make(chan chan error)

		for {
			select {
			case <-hup:
				level.Info(logger).Log("msg", "got SIGHUP signal")
				if err := reloadConfig(cmp); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
				} else {
					level.Info(logger).Log("msg", "Config has been successfully reloaded", "file", cmdConfigFile)
				}
			case rc := <-chHTTPReload:
				level.Info(logger).Log("msg", "got http config reload signal")
				if err := reloadConfig(cmp); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					rc <- err
				} else {
					level.Info(logger).Log("msg", "Config has been successfully reloaded", "file", cmdConfigFile)
					rc <- nil
				}
			}
		}
	}()

	// run handlers
	r := mux.NewRouter()
	r = r.Methods("GET").Subrouter()
	if Cfg.Server.Authentication {
		r.Use(amp.CheckAuth)
	}

	if Cfg.Server.API {
		r.Handle("/api/v1/series", fmp.FilterQuery("match[]", serveReverseProxy(Cfg.Server.Proxy))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/series", "server.uri.methods", "GET")
		r.Handle("/api/v1/query", fmp.FilterQuery("query", serveReverseProxy(Cfg.Server.Proxy))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/query", "server.uri.methods", "GET")
		r.Handle("/api/v1/query_range", fmp.FilterQuery("query", serveReverseProxy(Cfg.Server.Proxy))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/query_range", "server.uri.methods", "GET")
	}
	if Cfg.Server.Federate {
		r.Handle("/federate", fmp.FilterQuery("match[]", serveReverseProxy(Cfg.Server.Proxy))).Methods("GET")
	}
	if Cfg.Server.APIVMLabels {
		r.Handle("/api/v1/label/{label}/values", fmp.FilterQuery("match[]", serveReverseProxy(Cfg.Server.Proxy))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/label/*/valuese", "server.uri.methods", "GET")
		r.Handle("/api/v1/labels", fmp.FilterQuery("match[]", serveReverseProxy(Cfg.Server.Proxy))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/labels", "server.uri.methods", "GET")
	}

	srv := &http.Server{
		Handler:      r,
		Addr:         ":" + Cfg.Server.Port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			level.Error(logger).Log("msg", "main http listener error", "err", err)
			os.Exit(2)
		}
	}()

	if Cfg.Server.AdminAPI {
		ra := mux.NewRouter()
		ra.Handle("/admin/config/reload", reloadConfigHandler()).Methods("POST", "PUT")
		level.Info(logger).Log("admin.port", Cfg.Server.AdminPort)
		level.Info(logger).Log("admin.uri", "/admin/config/reload", "admin.uri.methods", "POST,PUT")
		srvadmin := &http.Server{
			Handler:      ra,
			Addr:         ":" + Cfg.Server.AdminPort,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}
		go func() {
			if err := srvadmin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				level.Error(logger).Log("msg", "listener admin http error", "err", err)
			}
		}()
	}

	chStop := make(chan os.Signal, 1)
	signal.Notify(chStop, os.Interrupt, syscall.SIGTERM)

	signal := <-chStop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = srv.Shutdown(ctx); err != nil {
		level.Error(logger).Log("msg", "error during server shutdown", "err", err)
	}
	level.Info(logger).Log("msg", "server has been shutted down", "signal", signal)
	os.Exit(0)

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
		logger = level.NewFilter(logger, level.AllowInfo())
	}
	return logger
}

func reloadConfig(cmp *config.ConfigManager) error {
	cfg, err := cmp.LoadConfig()
	if err != nil {
		return errors.Wrapf(err, "cannot load config file ")
	}

	newAmp := auth.NewManager(&logger)
	if cfg.Server.Authentication {
		authMemMap, err := config.ExtractAuthMap(&cfg)
		if err != nil {
			return errors.Wrapf(err, "error extracting auth map from config")
		}
		err = newAmp.ApplyConfig(cfg.Server.HeaderName, authMemMap)
		if err != nil {
			return errors.Wrapf(err, "error create new auth config")
		}
	}

	newFmp := filter.NewManager(&logger)
	matchMap, injectMap, err := config.ExtractFilterMap(&cfg)
	if err != nil {
		return errors.Wrapf(err, "error extracting filter map from config")
	}
	err = newFmp.ApplyConfig(cfg.Server.HeaderName, matchMap, injectMap)
	if err != nil {
		return errors.Wrapf(err, "error create new filter config")
	}

	// finally apply all

	Cfg = cfg

	err = amp.CopyConfig(newAmp)
	if err != nil {
		return errors.Wrapf(err, "error apply new auth config")
	}
	err = fmp.CopyConfig(newFmp)
	if err != nil {
		return errors.Wrapf(err, "error apply new filter config")
	}

	return nil
}

// reverse proxy
func serveReverseProxy(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url, _ := url.Parse(target)
		proxy := httputil.NewSingleHostReverseProxy(url)
		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = url.Host
		r.RequestURI = url.EscapedPath() + r.RequestURI
		level.Debug(logger).Log("send form", fmt.Sprintf("%v", r.Form))
		proxy.ServeHTTP(w, r)
	})
}

func reloadConfigHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		level.Debug(logger).Log("msg", "got reload config request")
		rc := make(chan error)
		chHTTPReload <- rc
		if err := <-rc; err != nil {
			http.Error(w, fmt.Sprintf("failed to reload config: %s\n", err), http.StatusInternalServerError)
		} else {
			fmt.Fprintf(w, "config has been successfully reloaded\n")
		}
	})
}
