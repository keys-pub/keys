// Package http provides a http client.
package http

import (
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

func httpClient() *http.Client {
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

func doRequest(client *http.Client, req *Request, headers []Header, options ...func(*http.Request)) (http.Header, []byte, error) {
	logger.Debugf("Requesting %s %s", req.Method, req.URL)

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

// Client defines how to request a resource.
type Client interface {
	Request(ctx context.Context, req *Request, headers []Header) ([]byte, error)
}

type client struct{}

// NewClient creates a Requestor for HTTP URLs.
func NewClient() Client {
	return client{}
}

// Request an URL.
func (c client) Request(ctx context.Context, req *Request, headers []Header) ([]byte, error) {
	_, body, err := doRequest(httpClient(), req, headers)
	if err != nil {
		logger.Warningf("Failed request: %s", err)
	}
	return body, err
}

type mockResponse struct {
	data []byte
	err  error
}

var _ Client = &Mock{}

// Mock ...
type Mock struct {
	resp map[string]*mockResponse
}

// NewMock with mocked responses.
func NewMock() *Mock {
	return &Mock{resp: map[string]*mockResponse{}}
}

// SetResponse ...
func (r *Mock) SetResponse(url string, b []byte) {
	r.resp[url] = &mockResponse{data: b}
}

// Response returns mocked response.
func (r *Mock) Response(url string) ([]byte, error) {
	// TODO: Match on method without params, etc.
	resp, ok := r.resp[url]
	if !ok {
		panic(errors.Errorf("no mock response for %s", url))
	}
	logger.Debugf("Mock response %s, data=%d; err=%s", url, len(resp.data), resp.err)
	// logger.Debugf("Mock data: %s", string(resp.data))
	return resp.data, resp.err
}

// SetError sets response error for ur
func (r *Mock) SetError(url string, err error) {
	r.resp[url] = &mockResponse{err: err}
}

// Request mock response.
func (r *Mock) Request(ctx context.Context, req *Request, headers []Header) ([]byte, error) {
	return r.Response(req.URL.String())
}
