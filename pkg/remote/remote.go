package remote

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// Manager describe set of auth maps (auth: id)
type Manager struct {
	url     *url.URL
	Client  http.Client
	headers map[string]string

	logger kitlog.Logger
	mtx    sync.RWMutex
}

// NewManager creates new instance
func NewManager(l *kitlog.Logger) *Manager {

	defurl, _ := url.Parse("http://localhost:9090")

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}
	client := http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}
	return &Manager{
		url:     defurl,
		Client:  client,
		headers: make(map[string]string, 0),
		logger:  *l,
	}
}

// ApplyConfig apply new config
func (rm *Manager) ApplyConfig(urlstr string, tlsVerify bool, headers map[string]string) error {

	rm.mtx.Lock()
	defer rm.mtx.Unlock()

	newurl, err := url.Parse(urlstr)
	if err != nil {
		level.Error(rm.logger).Log("msg", "Error parse url", "err", err)
		return err
	}
	rm.url = newurl

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsVerify}}
	rm.Client = http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	rm.headers = headers

	return nil
}

// CopyConfig apply new config from another manager
func (rm *Manager) CopyConfig(manager *Manager) error {
	rm.mtx.Lock()
	defer rm.mtx.Unlock()

	rm.url = manager.url
	rm.Client = manager.Client
	rm.headers = manager.headers

	return nil
}

// ServeReverseProxy serve reverse proxy
// func (rm *Manager) ServeReverseProxy() http.Handler {
func (rm *Manager) ServeReverseProxy(w http.ResponseWriter, r *http.Request) {
	// return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	proxy := httputil.NewSingleHostReverseProxy(rm.url)
	r.URL.Host = rm.url.Host
	r.URL.Scheme = rm.url.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	for k, v := range rm.headers {
		r.Header.Set(k, v)
	}
	r.Host = rm.url.Host
	r.RequestURI = rm.url.EscapedPath() + r.RequestURI // not sure
	level.Debug(rm.logger).Log("send uri", fmt.Sprintf("%v", r))
	proxy.ServeHTTP(w, r)
	// })
}
