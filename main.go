package main

import (
	"encoding/base64"
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
	HeaderName     string `yaml:"auth-header,omitempty"`
}

type ClientConfig struct {
	ID    string     `yaml:"id"`
	Auth  AuthSchema `yaml:"auth"`
	Match []string   `yaml:"match"`
}

var (
	err error

	//Cfg default config
	Cfg = AppConfig{
		ConfigFile: "config.yaml",
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
	c.Flag("c", "Configuration file path.").StringVar(&Cfg.ConfigFile)

	// read configfile
	file, err := ioutil.ReadFile(Cfg.ConfigFile)
	if err != nil {
		panic(err)
	}
	err = yaml.UnmarshalStrict(file, &Cfg)
	if err != nil {
		log.Fatalf("cannot parse configfile: %v", err)
	}
	log.Printf("Server config \n%v\n", Cfg.Server)

	// set inMem auth maps from config
	authHeaderName = Cfg.Server.HeaderName
	if Cfg.Server.Authentication {
		authMemBasicMap = make(map[string]string)
		authMemBearerMap = make(map[string]string)
		for _, c := range Cfg.Clients {
			// Header id set for Auth-enabled-cases
			if c.Auth.Header {
				authMemHeaderSet = append(authMemHeaderSet, c.ID)
			}
			// Basic base64-id map
			if c.Auth.Basic.User != "" && c.Auth.Basic.Password != "" {
				strb := []byte(c.Auth.Basic.User + ":" + c.Auth.Basic.Password)
				str := base64.StdEncoding.EncodeToString(strb)
				authMemBasicMap[str] = c.ID
			}
			// Bearer token-id map
			if c.Auth.Bearer.Token != "" {
				authMemBearerMap[c.Auth.Bearer.Token] = c.ID
			}
		}
	}
	// log.Printf("DEBUG: Auth Basic : %v\n\n", authMemBasicMap)
	// log.Printf("DEBUG: Auth Bearer : %v\n\n", authMemBearerMap)
	// log.Printf("DEBUG: Auth headers : %v\n\n", authMemHeaderSet)

	// set inMem matcher sets from config
	idHeaderName = Cfg.Server.HeaderName
	matchMemSet = make(map[string]MatcherSet)
	for _, c := range Cfg.Clients {
		AddMemMatcherSets(c.ID, c.Match)
		log.Printf("DEBUG: Matcher Set ID: %v Set: %v\n", c.ID, matchMemSet[c.ID])
	}

	http.Handle("/federate", handleGet(
		CheckAuth(
			FilterMatches(
				serveReverseProxy(Cfg.Server.Proxy)))))

	if err := http.ListenAndServe(":"+Cfg.Server.Port, nil); err != nil {
		panic(err)
	}
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

		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = url.Host

		// requestDump(r, "outgoing request")

		proxy.ServeHTTP(w, r)
	})
}

func requestDump(r *http.Request, comment string) {
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	log.Printf("DEBUG: "+comment+" : %s\n", requestDump)
}
