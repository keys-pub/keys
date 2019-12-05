package keys

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
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
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: transport,
	}
	return client
}

func doRequest(client *http.Client, method string, u string, body []byte, options ...func(*http.Request)) (http.Header, []byte, error) {
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
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

// Requestor defines how to get bytes from a URL.
type Requestor interface {
	RequestURL(ctx context.Context, u *url.URL) ([]byte, error)
}

type requestor struct{}

// NewHTTPRequestor creates a Requestor for HTTP URLs.
func NewHTTPRequestor() Requestor {
	return requestor{}
}

// RequestURL requests a URL.
func (r requestor) RequestURL(ctx context.Context, u *url.URL) ([]byte, error) {
	logger.Infof("Requesting URL %s", u)
	_, body, err := doRequest(client(), "GET", u.String(), nil)
	if err != nil {
		logger.Warningf("Failed request %s", err)
		if errHTTP, ok := errors.Cause(err).(ErrHTTP); ok {
			if errHTTP.StatusCode == 404 {
				err = NewErrTemporary(fmt.Sprintf("http not found %s", u))
			}
		}
	}
	return body, err
}
