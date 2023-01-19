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
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
)

const (
	namespace = "prom_liver"
	subsystem = "remote"
)

var (
	// RemoteRequestDuration is a histogram of latencies for remote data fetch.
	RemoteRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "duration_seconds",
			Help:      "A histogram of latencies for remote data fetch.",
			Buckets:   []float64{0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0, 3.0, 10.0},
		},
		[]string{"function"},
	)
)

var ErrorRemoteStatusCode = errors.New("unexpected HTTP status")
var ErrorRemoteStatus400 = fmt.Errorf("%w: HTTP 400", ErrorRemoteStatusCode)
var ErrorRemoteStatus422 = fmt.Errorf("%w: HTTP 422", ErrorRemoteStatusCode)
var ErrorRemoteStatus503 = fmt.Errorf("%w: HTTP 503", ErrorRemoteStatusCode)

// Manager describe set of auth maps (auth: id)
type Manager struct {
	url     *url.URL
	timeout time.Duration
	Client  http.Client
	headers http.Header

	logger kitlog.Logger
	mtx    sync.RWMutex
}

// NewManager creates new instance
func NewManager(l *kitlog.Logger) *Manager {

	defurl, _ := url.Parse("http://localhost:9090")

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}
	timeout := 10 * time.Second
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	return &Manager{
		url:     defurl,
		timeout: timeout,
		Client:  client,
		headers: headers,
		logger:  *l,
	}
}

// ApplyConfig apply new config
func (rm *Manager) ApplyConfig(urlstr string, timeout int64, tlsVerify bool, caCert []byte, headers map[string]string) error {

	rm.mtx.Lock()
	defer rm.mtx.Unlock()

	newurl, err := url.Parse(urlstr)
	if err != nil {
		level.Error(rm.logger).Log("msg", "Error parse url", "err", err)
		return err
	}
	rm.url = newurl

	rm.timeout = time.Duration(timeout) * time.Second

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
		Timeout:   rm.timeout,
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
	rm.timeout = manager.timeout
	rm.Client = manager.Client
	rm.headers = manager.headers
	rm.headers.Set("Content-Type", "application/x-www-form-urlencoded")

	return nil
}

// ServeReverseProxy serve reverse proxy
func (rm *Manager) ServeReverseProxy(w http.ResponseWriter, r *http.Request) {

	timer := prometheus.NewTimer(RemoteRequestDuration.WithLabelValues("reverse-proxy"))
	defer timer.ObserveDuration()

	proxy := httputil.NewSingleHostReverseProxy(rm.url)
	r.URL.Host = rm.url.Host
	r.URL.Scheme = rm.url.Scheme
	r.Header = rm.headers
	r.Host = rm.url.Host
	r.RequestURI = rm.url.EscapedPath() + r.RequestURI
	level.Debug(rm.logger).Log("proxy", fmt.Sprintf("%v", r))
	proxy.ServeHTTP(w, r)
}

// FetchResult serve r
func (rm *Manager) FetchResult(ctx context.Context, path string, query url.Values) (result APIResponse, err error) {
	timer := prometheus.NewTimer(RemoteRequestDuration.WithLabelValues("single-fetch"))
	defer timer.ObserveDuration()

	ctx, cancel := context.WithTimeout(ctx, rm.timeout)
	defer cancel()

	result = APIResponse{}

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
	level.Debug(rm.logger).Log("request", fmt.Sprintf("%v", req))
	resp, err := rm.Client.Do(&req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return result, err
	}

	switch resp.StatusCode {
	case 200:
		return result, nil
	case 400:
		return result, ErrorRemoteStatus400
	case 422:
		return result, ErrorRemoteStatus422
	case 503:
		return result, ErrorRemoteStatus503
	default:
		return ErrorAPIResponse(v1.ErrBadResponse, fmt.Errorf("%v", resp.StatusCode)), ErrorRemoteStatusCode
	}

}

type subResult struct {
	res APIResponse
	err error
}

// FetchMultiQueryResult returns union of subqueries
func (rm *Manager) FetchMultiQueryResult(ctx context.Context, path string, query url.Values, subqueries []string) (APIResponse, error) {
	timer := prometheus.NewTimer(RemoteRequestDuration.WithLabelValues("multi-fetch"))
	defer timer.ObserveDuration()

	resultsChan := make(chan *subResult, len(subqueries))
	defer func() {
		close(resultsChan)
	}()

	level.Debug(rm.logger).Log("multi-fetch ", fmt.Sprintf("%v", len(subqueries)))
	wg := sync.WaitGroup{}
	for _, subq := range subqueries {
		wg.Add(1)
		go func(ctx context.Context, path string, query url.Values, subq string) {
			defer wg.Done()
			subQuery := make(url.Values, len(query))
			for k := range query {
				subQuery[k] = query[k]
			}
			subQuery.Set("query", subq)
			res, err := rm.FetchResult(ctx, path, subQuery)
			resultsChan <- &subResult{res, err}
		}(ctx, path, query, subq)
	}

	wg.Wait()
	mData := DefaultAPIResponse()
	var mResult []interface{}
	for i := 0; i < len(subqueries); i++ {
		subRes := <-resultsChan
		if subRes.err != nil {
			level.Error(rm.logger).Log("msg", "error subquery", subRes.err)
			return subRes.res, subRes.err
		}
		// TODO: data type correct checks
		mData = subRes.res
		switch subRes.res.Data.Type {
		case model.ValMatrix, model.ValVector:
			mResult = append(mResult, subRes.res.Data.Result.([]interface{})...)
		case model.ValScalar, model.ValString:
			mResult = subRes.res.Data.Result.([]interface{})
		}
	}
	if len(mResult) > 0 {
		mData.Data.Result = mResult
	}
	return mData, nil
}
