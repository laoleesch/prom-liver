package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/common/model"
)

// Manager describe set of auth maps (auth: id)
type Manager struct {
	url     *url.URL
	Client  http.Client
	headers http.Header

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

	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	return &Manager{
		url:     defurl,
		Client:  client,
		headers: headers,
		logger:  *l,
	}
}

// ApplyConfig apply new config
func (rm *Manager) ApplyConfig(urlstr string, tlsVerify bool, caCert []byte, headers map[string]string) error {

	rm.mtx.Lock()
	defer rm.mtx.Unlock()

	newurl, err := url.Parse(urlstr)
	if err != nil {
		level.Error(rm.logger).Log("msg", "Error parse url", "err", err)
		return err
	}
	rm.url = newurl

	tlsConfig := &tls.Config{InsecureSkipVerify: tlsVerify}
	if len(caCert) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig = &tls.Config{
			InsecureSkipVerify: tlsVerify,
			RootCAs:            caCertPool,
		}
	}

	tr := &http.Transport{TLSClientConfig: tlsConfig}
	rm.Client = http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	rm.headers = make(http.Header)
	for k, v := range headers {
		rm.headers.Add(k, v)
	}
	rm.headers.Set("Content-Type", "application/x-www-form-urlencoded")

	return nil
}

// CopyConfig apply new config from another manager
func (rm *Manager) CopyConfig(manager *Manager) error {
	rm.mtx.Lock()
	defer rm.mtx.Unlock()

	rm.url = manager.url
	rm.Client = manager.Client
	rm.headers = manager.headers
	rm.headers.Set("Content-Type", "application/x-www-form-urlencoded")

	return nil
}

// ServeReverseProxy serve reverse proxy
// func (rm *Manager) ServeReverseProxy() http.Handler {
func (rm *Manager) ServeReverseProxy(w http.ResponseWriter, r *http.Request) {
	// return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	proxy := httputil.NewSingleHostReverseProxy(rm.url)
	r.URL.Host = rm.url.Host
	r.URL.Scheme = rm.url.Scheme
	r.Header = rm.headers
	r.Host = rm.url.Host
	r.RequestURI = rm.url.EscapedPath() + r.RequestURI // not sure
	level.Debug(rm.logger).Log("send uri", fmt.Sprintf("%v", r))
	proxy.ServeHTTP(w, r)
	// })
}

// FetchResult serve r
func (rm *Manager) FetchResult(ctx context.Context, path string, query url.Values) (result APIResponse, err error) {

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result = APIResponse{Status: "error"}

	targetURL := *rm.url
	targetURL.RawPath = path
	targetURL.RawQuery = query.Encode()
	targetURL.Path = path

	req := http.Request{
		Method:     "GET",
		URL:        &targetURL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     rm.headers,
		Host:       targetURL.Host,
	}
	resp, err := rm.Client.Do(&req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return result, errors.New("unexpected HTTP status on " + resp.Request.URL.String() + ", rm.url,: " + fmt.Sprintf("%v", resp.StatusCode))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return result, err
	}

	return result, nil

}

// FetchMultiQueryResult returns union of subqueries
func (rm *Manager) FetchMultiQueryResult(ctx context.Context, path string, query url.Values, subqueries []string) (APIResponse, error) {
	var mData APIResponse
	var result []interface{}
	for _, subq := range subqueries {
		query.Set("query", subq)
		data, err := rm.FetchResult(ctx, path, query)
		if err != nil {
			level.Error(rm.logger).Log("msg", "error getting data", err)
			return data, err
		}
		mData = data
		switch data.Data.Type {
		case model.ValMatrix, model.ValVector:
			result = append(result, data.Data.Result.([]interface{})...)
		case model.ValScalar, model.ValString:
			result = data.Data.Result.([]interface{})
		}
	}
	if len(result) > 0 {
		mData.Data.Result = result
	}
	return mData, nil
}
