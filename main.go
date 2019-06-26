package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

type parameter struct {
	Key, Value string
}

var config map[string]parameter
var err error

func configDefault() {
	config = make(map[string]parameter)
	config["listen_port"] = parameter{
		"PK_PORT", ":8080",
	}
	config["proxy_url"] = parameter{
		"PK_PROXY_URL", "http://localhost:9090",
	}
}

func configCheckEnv(p parameter) {
	if value, ok := os.LookupEnv(p.Key); ok {
		p.Value = value
	}
}

func configInit() {
	log.Printf("INFO: Config initialisation.\n")
	configDefault()
	for p := range config {
		configCheckEnv(config[p])
		log.Printf("INFO: %s = %s\n", config[p].Key, config[p].Value)
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
		serveReverseProxy(config["proxy_url"].Value, res, req)
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

func main() {

	configInit()

	http.HandleFunc("/federate", handleRequestAndRedirect)

	if err := http.ListenAndServe(config["listen_port"].Value, nil); err != nil {
		panic(err)
	}
}
