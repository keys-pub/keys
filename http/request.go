package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/keys-pub/keys"
)

// NewRequest alias.
var NewRequest = http.NewRequest

// NewRequestWithContext alias.
var NewRequestWithContext = http.NewRequestWithContext

// NewAuthRequest returns new authorized/signed HTTP request using auth key.
func NewAuthRequest(method string, urs string, body io.Reader, contentHash string, ts time.Time, key *keys.EdX25519Key) (*http.Request, error) {
	return newRequest(method, urs, body, contentHash, ts, keys.RandBytes(24), key)
}

func newRequest(method string, urs string, body io.Reader, contentHash string, ts time.Time, nonce []byte, key *keys.EdX25519Key) (*http.Request, error) {
	ur, err := authURL(urs, ts, nonce)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, ur.String(), body)
	if err != nil {
		return nil, err
	}
	a, err := newAuthWithURL(method, ur, contentHash, key)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.Header())
	return req, nil
}

// NewJSONRequest ...
func NewJSONRequest(method string, urs string, i interface{}, opt ...RequestOption) (*http.Request, error) {
	opts := NewRequestOptions(opt...)
	b, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	if opts.Key != nil {
		ts := opts.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		return NewAuthRequest(method, urs, bytes.NewReader(b), ContentHash(b), ts, opts.Key)
	}
	return NewRequest(method, urs, bytes.NewReader(b))
}

// RequestOptions ...
type RequestOptions struct {
	Timestamp time.Time
	Key       *keys.EdX25519Key
}

// RequestOption ...
type RequestOption func(*RequestOptions)

// NewRequestOptions parses RequestOption.
func NewRequestOptions(opts ...RequestOption) RequestOptions {
	var options RequestOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// WithTimestamp to overwride timestamp.
func WithTimestamp(ts time.Time) RequestOption {
	return func(o *RequestOptions) {
		o.Timestamp = ts
	}
}

// SignedWith key.
func SignedWith(key *keys.EdX25519Key) RequestOption {
	return func(o *RequestOptions) {
		o.Key = key
	}
}
