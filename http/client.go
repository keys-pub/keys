// Package http provides an http client for use with checking remote signed
// statements.
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
)

// ErrTimeout is a timeout error.
type ErrTimeout struct {
	error
}

// Error is an HTTP Error.
type Error struct {
	StatusCode int
}

func (e Error) Error() string {
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
		Timeout:   time.Second * 30,
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
		return resp.Header, nil, Error{StatusCode: resp.StatusCode}
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

// Client for HTTP.
type Client interface {
	Request(ctx context.Context, req *Request, headers []Header) ([]byte, error)
	SetProxy(urs string, fn ProxyFn)
}

type client struct {
	proxies map[string]ProxyFn
}

// NewClient creates a Requestor for HTTP URLs.
func NewClient() Client {
	return &client{}
}

// ProxyFn for proxy.
type ProxyFn func(ctx context.Context, req *Request, headers []Header) ProxyResponse

// ProxyResponse ...
type ProxyResponse struct {
	Skip bool
	Body []byte
	Err  error
}

// ProxyAdd on client.
func (c *client) SetProxy(urs string, fn ProxyFn) {
	if c.proxies == nil {
		c.proxies = map[string]ProxyFn{}
	}
	c.proxies[urs] = fn
}

// Request an URL.
func (c *client) Request(ctx context.Context, req *Request, headers []Header) ([]byte, error) {
	if c.proxies != nil {
		fn := c.proxies[req.URL.String()]
		if fn != nil {
			pr := fn(ctx, req, headers)
			if !pr.Skip {
				return pr.Body, pr.Err
			}
		}
		fn = c.proxies[""]
		if fn != nil {
			pr := fn(ctx, req, headers)
			if !pr.Skip {
				return pr.Body, pr.Err
			}
		}
	}
	_, body, err := doRequest(httpClient(), req, headers)
	if err != nil {
		logger.Warningf("Failed request: %s", err)
	}
	return body, err
}
