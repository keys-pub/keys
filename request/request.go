// Package request provides clients for requesting data.
package request

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// ErrTimeout is a timeout error.
type ErrTimeout struct {
	error
}

// ErrHTTP is an HTTP Error.
type ErrHTTP struct {
	StatusCode int
}

func (e ErrHTTP) Error() string {
	return fmt.Sprintf("http error %d", e.StatusCode)
}

func client() *http.Client {
	// TODO: Longer timeout?
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: transport,
		// Important not to follow redirects.
		// Twitter may redirect invalid urls with a valid status.
		// We do allow a redirect if it's just a case change.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 1 {
				if strings.EqualFold(req.URL.String(), via[0].URL.String()) {
					return nil
				}
			}

			return http.ErrUseLastResponse
		},
	}
	return client
}

func doRequest(client *http.Client, method string, urs string, headers []Header, body []byte, options ...func(*http.Request)) (http.Header, []byte, error) {
	logger.Debugf("Requesting %s %s", method, urs)
	req, err := http.NewRequest(method, urs, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", "keys.pub")
	for _, header := range headers {
		req.Header.Set(header.Name, header.Value)
	}

	for _, opt := range options {
		opt(req)
	}

	resp, err := client.Do(req)
	switch err := err.(type) {
	default:
		return nil, nil, err
	case nil:
		// no error

	case *url.Error:
		// `http.Client.Do` will return a `url.Error` that wraps a `net.Error`
		// when exceeding it's `Transport`'s `ResponseHeadersTimeout`
		e1, ok := err.Err.(net.Error)
		if ok && e1.Timeout() {
			return nil, nil, ErrTimeout{err}
		}

		return nil, nil, err

	case net.Error:
		// `http.Client.Do` will return a `net.Error` directly when Dial times
		// out, or when the Client's RoundTripper otherwise returns an err
		if err.Timeout() {
			return nil, nil, ErrTimeout{err}
		}

		return nil, nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode/200 != 1 {
		return resp.Header, nil, ErrHTTP{StatusCode: resp.StatusCode}
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	logger.Debugf("Response body (len=%d)", len(respBody))

	return resp.Header, respBody, nil
}

// ErrTemporary means there was a temporary error
type ErrTemporary struct {
	msg string
}

// NewErrTemporary creates temporary error.
func NewErrTemporary(msg string) ErrTemporary {
	return ErrTemporary{msg: msg}
}

func (e ErrTemporary) Error() string {
	return fmt.Sprintf("temporary error: %s", e.msg)
}

// Temporary returns true.
func (e ErrTemporary) Temporary() bool {
	return true
}

// Header for request.
type Header struct {
	Name  string
	Value string
}

// Requestor defines how to request a resource.
type Requestor interface {
	Get(ctx context.Context, urs string, headers []Header) ([]byte, error)
}

type requestor struct{}

// NewHTTPRequestor creates a Requestor for HTTP URLs.
func NewHTTPRequestor() Requestor {
	return requestor{}
}

// Get an URL.
func (r requestor) Get(ctx context.Context, urs string, headers []Header) ([]byte, error) {
	_, body, err := doRequest(client(), "GET", urs, headers, nil)
	if err != nil {
		logger.Warningf("Failed request: %s", err)
	}
	return body, err
}

type mockResponse struct {
	data []byte
	err  error
}

var _ Requestor = &MockRequestor{}

// MockRequestor ...
type MockRequestor struct {
	resp map[string]*mockResponse
}

// NewMockRequestor with mocked responses.
func NewMockRequestor() *MockRequestor {
	return &MockRequestor{resp: map[string]*mockResponse{}}
}

// SetResponse ...
func (r *MockRequestor) SetResponse(url string, b []byte) {
	r.resp[url] = &mockResponse{data: b}
}

// Response returns mocked response.
func (r *MockRequestor) Response(url string) ([]byte, error) {
	resp, ok := r.resp[url]
	if !ok {
		return nil, errors.Errorf("no mock response for %s", url)
	}
	logger.Debugf("Mock response %s, data=%d; err=%s", url, len(resp.data), resp.err)
	// logger.Debugf("Mock data: %s", string(resp.data))
	return resp.data, resp.err
}

// SetError sets response error for ur
func (r *MockRequestor) SetError(url string, err error) {
	r.resp[url] = &mockResponse{err: err}
}

// Get mock response.
func (r *MockRequestor) Get(ctx context.Context, urs string, headers []Header) ([]byte, error) {
	return r.Response(urs)
}
