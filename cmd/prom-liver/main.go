package main

import (

	// _ "net/http/pprof"

	"context"
	"encoding/base64"
	"fmt"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"crypto/tls"

	config "github.com/laoleesch/prom-liver/internal/config"
	auth "github.com/laoleesch/prom-liver/pkg/auth"
	filter "github.com/laoleesch/prom-liver/pkg/filter"
)

var (
	logger kitlog.Logger

	// cmd args
	configFile    = kingpin.Flag("config", "Configuration file").Short('c').Default("config.yaml").String()
	logLevel      = kingpin.Flag("loglevel", "Log filtering level").Short('l').Default("info").Enum("debug", "info", "warning", "error")
	listenAddress = kingpin.Flag("bind", "Address to listen on.").Short('b').Default(":8080").String()

	// Cfg global config
	Cfg config.Config

	// reload config channel
	chHTTPReload chan chan error

	// managers
	cmp *config.Manager
	amp *auth.Manager
	fmp *filter.Manager
)

func main() {

	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	// init logger
	logger = initLogger(*logLevel)
	level.Info(logger).Log("loglevel", *logLevel)
	level.Info(logger).Log("configfile", *configFile)
	level.Info(logger).Log("bind", *listenAddress)

	// Init config
	Cfg = config.DefaultConfig()
	amp = auth.NewManager(&logger)
	fmp = filter.NewManager(&logger)

	cmp, err := config.New(*configFile, &logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error init ConfigManager", "err", err)
		os.Exit(2)
	}

	err = reloadConfig(cmp)
	if err != nil {
		level.Error(logger).Log("msg", "Error load config", "err", err)
		os.Exit(2)
	}

	level.Info(logger).Log("web.auth", Cfg.Web.Auth)
	level.Info(logger).Log("web.header", Cfg.Web.HeaderName)
	level.Info(logger).Log("remote.url", Cfg.Remote.URL)

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
					level.Info(logger).Log("msg", "Config has been successfully reloaded", "file", *configFile)
				}
			case rc := <-chHTTPReload:
				level.Info(logger).Log("msg", "got http config reload signal")
				if err := reloadConfig(cmp); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					rc <- err
				} else {
					level.Info(logger).Log("msg", "Config has been successfully reloaded", "file", *configFile)
					rc <- nil
				}
			}
		}
	}()

	// run handlers
	r := mux.NewRouter()
	r = r.Methods("GET").Subrouter()
	if Cfg.Web.Auth {
		r.Use(amp.CheckAuth)
	}

	if Cfg.Web.Handlers.API {
		r.Handle("/api/v1/series", fmp.FilterQuery("match[]", serveReverseProxy(Cfg.Remote.URL))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/series", "server.uri.methods", "GET")
		r.Handle("/api/v1/query", fmp.FilterQuery("query", serveReverseProxy(Cfg.Remote.URL))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/query", "server.uri.methods", "GET")
		r.Handle("/api/v1/query_range", fmp.FilterQuery("query", serveReverseProxy(Cfg.Remote.URL))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/query_range", "server.uri.methods", "GET")
	}
	if Cfg.Web.Handlers.Federate {
		r.Handle("/federate", fmp.FilterQuery("match[]", serveReverseProxy(Cfg.Remote.URL))).Methods("GET")
	}
	if Cfg.Web.Handlers.APIVMLabels {
		r.Handle("/api/v1/label/{label}/values", fmp.FilterQuery("match[]", serveReverseProxy(Cfg.Remote.URL))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/label/*/valuese", "server.uri.methods", "GET")
		r.Handle("/api/v1/labels", fmp.FilterQuery("match[]", serveReverseProxy(Cfg.Remote.URL))).Methods("GET")
		level.Info(logger).Log("server.uri", "/api/v1/labels", "server.uri.methods", "GET")
	}

	if Cfg.Web.Handlers.ConfigReload {
		r.Handle("/-/config/reload", reloadConfigHandler()).Methods("POST", "PUT")
		level.Info(logger).Log("server.uri", "/-/config/reload", "server.uri.methods", "POST,PUT")
	}

	srv := &http.Server{
		Handler:      r,
		Addr:         *listenAddress,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			level.Error(logger).Log("msg", "main http listener error", "err", err)
			os.Exit(2)
		}
	}()

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
		level.Error(logger).Log("msg", "wrong log level name", "value", *logLevel)
		logger = level.NewFilter(logger, level.AllowInfo())
	}
	return logger
}

func reloadConfig(cmp *config.Manager) error {
	cfg, err := cmp.LoadConfig()
	if err != nil {
		return errors.Wrapf(err, "cannot load config file ")
	}

	newAmp := auth.NewManager(&logger)
	if cfg.Web.Auth {
		authMemMap, err := config.ExtractAuthMap(&cfg)
		if err != nil {
			return errors.Wrapf(err, "error extracting auth map from config")
		}
		err = newAmp.ApplyConfig(cfg.Web.HeaderName, authMemMap)
		if err != nil {
			return errors.Wrapf(err, "error create new auth config")
		}
	}

	newFmp := filter.NewManager(&logger)
	matchMap, injectMap, filterMap, err := config.ExtractFilterMap(&cfg)
	if err != nil {
		return errors.Wrapf(err, "error extracting filter map from config")
	}
	err = newFmp.ApplyConfig(cfg.Web.HeaderName, matchMap, injectMap, filterMap)
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

		if !Cfg.Remote.TLS.Verify {
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}

		url, _ := url.Parse(target)
		proxy := httputil.NewSingleHostReverseProxy(url)
		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		if Cfg.Remote.Auth.User != "" && Cfg.Remote.Auth.Password != "" {
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(Cfg.Remote.Auth.User))+
				":"+base64.StdEncoding.EncodeToString([]byte(Cfg.Remote.Auth.Password)))
		}
		if Cfg.Remote.Auth.Token != "" {
			r.Header.Set("Authorization", "Bearer "+Cfg.Remote.Auth.Token)
		}
		r.Host = url.Host
		r.RequestURI = url.EscapedPath() + r.RequestURI
		level.Debug(logger).Log("send uri", fmt.Sprintf("%v", r))
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
