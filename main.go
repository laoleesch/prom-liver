package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

type AppConfig struct {
	ConfigFile string
	Server     ServerConfig   `yaml:"server,omitempty"`
	Clients    []ClientConfig `yaml:"clients"`
}

type ServerConfig struct {
	Port           string `yaml:"port,omitempty"`
	Proxy          string `yaml:"proxy,omitempty"`
	Authentication bool   `yaml:"authentication,omitempty"`
	// Authschemes []string `yaml:"authschemes,omitempty"`
}

type ClientConfig struct {
	ID    string     `yaml:"id"`
	Auth  AuthSchema `yaml:"auth"`
	Match MatchSet   `yaml:"match"`
}

type AuthSchema struct {
	Header bool             `yaml:"header,omitempty"` //header 'X-Prom-Liver-Id' value
	Basic  AuthSchemaBasic  `yaml:"basic,omitempty"`
	Bearer AuthSchemaBearer `yaml:"bearer,omitempty"`
}

type AuthSchemaBasic struct {
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
	// Base64   string `yaml:"base64,omitempty"`
	File string `yaml:"file,omitempty"`
}

type AuthSchemaBearer struct {
	Token string `yaml:"token,omitempty"`
	File  string `yaml:"file,omitempty"`
}

var (
	err error

	//Cfg default config
	Cfg = AppConfig{
		ConfigFile: "config.yaml",
		Server: ServerConfig{
			Port:           "8080",
			Proxy:          "http://localhost:9090",
			Authentication: true,
		},
	}
)

func main() {

	// set config
	c := kingpin.New(filepath.Base(os.Args[0]), "Auth-filter-reverse-proxy-server for Prometheus federate")

	c.HelpFlag.Short('h')

	// get configfile
	c.Flag("configfile", "Configuration file path.").StringVar(&Cfg.ConfigFile)

	// read configfile
	file, err := ioutil.ReadFile(Cfg.ConfigFile)
	if err != nil {
		panic(err)
	}
	err = yaml.UnmarshalStrict(file, &Cfg)
	if err != nil {
		log.Fatalf("cannot parse configfile: %v", err)
	}

	log.Printf("DEBUG: config \n%v\n", Cfg.Server)

	// set AuthSets from config
	// Header Value-id map

	// Basic base64-id map

	// Bearer token-id map

	// start reverse proxy
	http.Handle("/federate", hFilterGet(
		handleRequestAndRedirect(
			Cfg.Server.Authentication,
			Cfg.Server.Proxy)))

	if err := http.ListenAndServe(":"+Cfg.Server.Port, nil); err != nil {
		panic(err)
	}
}

// main "handler"
func handleRequestAndRedirect(isAuth bool, target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			fmt.Println(err)
		}
		log.Printf("DEBUG: incoming request : %s\n", requestDump)

		if !isAuth {
			return //!TODO
		}
		CheckAuth(serveReverseProxy(target))
	})
}

// filter non-GET requests
func hFilterGet(h http.Handler) http.Handler {
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
		log.Printf("DEBUG: reverse proxy url : %s\n", url)
		proxy := httputil.NewSingleHostReverseProxy(url)

		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = url.Host

		requestDump, err := httputil.DumpRequestOut(r, true)
		if err != nil {
			fmt.Println(err)
		}
		log.Printf("DEBUG: outgoing request : %s\n", requestDump)

		proxy.ServeHTTP(w, r)
	})
}
