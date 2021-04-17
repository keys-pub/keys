package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	nethttp "net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

// Client ...
type Client struct {
	url        *url.URL
	httpClient *nethttp.Client
	clock      tsutil.Clock
}

// New creates a Client for the a Web API.
func New(urs string) (*Client, error) {
	urs = strings.TrimSuffix(urs, "/")
	urp, err := url.Parse(urs)
	if err != nil {
		return nil, err
	}

	return &Client{
		url:        urp,
		httpClient: defaultHTTPClient(),
		clock:      tsutil.NewClock(),
	}, nil
}

// SetHTTPClient sets the http.Client to use.
func (c *Client) SetHTTPClient(httpClient *nethttp.Client) {
	c.httpClient = httpClient
}

// HTTPClient we are using.
func (c *Client) HTTPClient() *nethttp.Client {
	return c.httpClient
}

// TODO: are these timeouts too agressive?
func defaultHTTPClient() *nethttp.Client {
	return &nethttp.Client{
		Timeout: time.Second * 30,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}

// URL ...
func (c *Client) URL() *url.URL {
	return c.url
}

// SetClock sets the clock Now fn.
func (c *Client) SetClock(clock tsutil.Clock) {
	c.clock = clock
}

func (c *Client) Clock() tsutil.Clock {
	return c.clock
}

func checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// Default error
	err := Error{Status: resp.StatusCode}

	b, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		return err
	}
	if len(b) == 0 {
		return err
	}
	var respVal APIResponse
	if err := json.Unmarshal(b, &respVal); err != nil {
		if utf8.Valid(b) {
			return errors.New(string(b))
		}
		return errors.Errorf("error response not valid utf8")
	}
	if respVal.Error != nil {
		err.Message = respVal.Error.Message
	}

	return err
}

func (c *Client) urlFor(path string, params url.Values) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return "", errors.Errorf("req accepts a path, not an url")
	}

	urs := c.url.String() + path
	query := params.Encode()
	if query != "" {
		urs = urs + "?" + query
	}
	return urs, nil
}

// Request ...
type Request struct {
	Method string
	Path   string
	Params url.Values
	Body   []byte
	// Key is shortcut for []Auths{{Header: "Authorization", Key: Key}}
	Key      *keys.EdX25519Key
	Headers  []http.Header
	Progress func(n int64)
	Auths    []http.AuthHeader
}

// ProgressReader reports progress while reading.
type progressReader struct {
	io.Reader
	Progress func(r int64)
}

func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.Reader.Read(p)
	pr.Progress(int64(n))
	return
}

// Request makes a request.
func (c *Client) Request(ctx context.Context, req *Request) (*Response, error) {
	urs, err := c.urlFor(req.Path, req.Params)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Client req %s %s", req.Method, urs)

	var reader io.Reader
	if req.Progress != nil {
		pr := &progressReader{}
		pr.Reader = bytes.NewReader(req.Body)
		pr.Progress = req.Progress
		reader = pr
	} else {
		reader = bytes.NewReader(req.Body)
	}

	if req.Key != nil {
		if req.Auths == nil {
			req.Auths = []http.AuthHeader{}
		}
		req.Auths = append(req.Auths, http.AuthHeader{Header: "Authorization", Key: req.Key})
	}

	var httpReq *http.Request
	if len(req.Auths) > 0 {
		r, err := http.NewAuthsRequest(req.Method, urs, reader, http.ContentHash(req.Body), c.clock.Now(), req.Auths)
		if err != nil {
			return nil, err
		}
		httpReq = r
	} else {
		r, err := http.NewRequest(req.Method, urs, reader)
		if err != nil {
			return nil, err
		}
		httpReq = r
	}

	for _, h := range req.Headers {
		httpReq.Header.Set(h.Name, h.Value)
	}

	resp, err := c.httpClient.Do(httpReq.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	if (req.Method == "GET" || req.Method == "HEAD") && resp.StatusCode == 404 {
		logger.Debugf("Not found %s", req.Path)
		return nil, nil
	}
	if err := checkResponse(resp); err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	return c.response(req.Path, resp)
}

// Response ...
type Response struct {
	Data      []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (c *Client) response(path string, resp *http.Response) (*Response, error) {
	b, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}

	createdHeader := resp.Header.Get("CreatedAt-RFC3339M")
	createdAt := time.Time{}
	if createdHeader != "" {
		tm, err := time.Parse(tsutil.RFC3339Milli, createdHeader)
		if err != nil {
			return nil, err
		}
		createdAt = tm
	}

	updatedHeader := resp.Header.Get("Last-Modified-RFC3339M")
	updatedAt := time.Time{}
	if updatedHeader != "" {
		tm, err := time.Parse(tsutil.RFC3339Milli, updatedHeader)
		if err != nil {
			return nil, err
		}
		updatedAt = tm
	}

	out := &Response{Data: b}
	out.CreatedAt = createdAt
	out.UpdatedAt = updatedAt
	return out, nil
}

// GET request.
func GET(path string, key *keys.EdX25519Key) *Request {
	return &Request{Method: "GET", Path: path, Key: key}
}

// PUT request.
func PUT(path string, body []byte, key *keys.EdX25519Key) *Request {
	return &Request{Method: "PUT", Path: path, Body: body, Key: key}
}
