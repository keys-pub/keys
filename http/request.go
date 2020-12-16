package http

import (
	"io"
	"net/http"
	"time"

	"github.com/keys-pub/keys"
)

// NewRequest alias.
var NewRequest = http.NewRequest

// NewRequestWithContext alias.
var NewRequestWithContext = http.NewRequestWithContext

// NewAuthRequest returns new authorized/signed HTTP request from keys.
func NewAuthRequest(method string, urs string, body io.Reader, contentHash string, tm time.Time, auth *keys.EdX25519Key) (*http.Request, error) {
	return newRequest(method, urs, body, contentHash, tm, keys.RandBytes(24), auth)
}

func newRequest(method string, urs string, body io.Reader, contentHash string, tm time.Time, nonce []byte, auth *keys.EdX25519Key) (*http.Request, error) {
	ur, err := authURL(urs, tm, nonce)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, ur.String(), body)
	if err != nil {
		return nil, err
	}
	a, err := newAuthWithURL(method, ur, contentHash, auth)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.Header())
	return req, nil
}
