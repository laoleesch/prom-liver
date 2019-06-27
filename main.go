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
	Port        string   `yaml:"port,omitempty"`
	Proxy       string   `yaml:"proxy,omitempty"`
	Authschemes []string `yaml:"authschemes,omitempty"`
}

type ClientConfig struct {
	Id    string     `yaml:"id"`
	Auth  AuthSchema `yaml:"auth"`
	Match []string   `yaml:"match"`
}

type AuthSchema struct {
	IP    string          `yaml:"ip,omitempty"`
	Basic AuthSchemaBasic `yaml:"basic,omitempty"`
}

type AuthSchemaBasic struct {
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"`
}

var (
	err error

	// default config
	cfg = AppConfig{
		ConfigFile: "config.yaml",
		Server: ServerConfig{
			Port:  "8080",
			Proxy: "http://localhost:9090",
			Authschemes: []string{
				"ip",
			},
		},
	}
)

func main() {

	// set config
	c := kingpin.New(filepath.Base(os.Args[0]), "Auth-filter-reverse-proxy-server for Prometheus federate")

	c.HelpFlag.Short('h')

	// get configfile
	c.Flag("configfile", "Configuration file path.").StringVar(&cfg.ConfigFile)

	// read configfile
	file, err := ioutil.ReadFile(cfg.ConfigFile)
	if err != nil {
		panic(err)
	}
	err = yaml.UnmarshalStrict(file, &cfg)
	if err != nil {
		log.Fatalf("cannot parse configfile: %v", err)
	}

	log.Printf("DEBUG: config \n%v\n", cfg.Server)

	// set clients config from yaml

	// start reverse proxy
	http.HandleFunc("/federate", handleRequestAndRedirect)

	if err := http.ListenAndServe(":"+cfg.Server.Port, nil); err != nil {
		panic(err)
	}
}

// main "handler"
func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {

	switch req.Method {
	case "GET":

		requestDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			fmt.Println(err)
		}
		log.Printf("DEBUG: incoming request : %s\n", requestDump)
		serveReverseProxy(cfg.Server.Proxy, res, req)
	}

}

// check lables
func filterMatches() {

}

// reverse proxy
func serveReverseProxy(target string, res http.ResponseWriter, req *http.Request) {
	url, _ := url.Parse(target)
	log.Printf("DEBUG: reverse proxy url : %s\n", url)
	proxy := httputil.NewSingleHostReverseProxy(url)

	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	req.Host = url.Host

	requestDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		fmt.Println(err)
	}
	log.Printf("DEBUG: outgoing request : %s\n", requestDump)

	proxy.ServeHTTP(res, req)
}
