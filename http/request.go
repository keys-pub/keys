package http

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/keys-pub/keys"
)

// NewRequest alias.
var NewRequest = http.NewRequest

// NewRequestWithContext alias.
var NewRequestWithContext = http.NewRequestWithContext

// NewAuthRequest returns new authorized/signed HTTP request.
func NewAuthRequest(method string, urs string, body io.Reader, contentHash string, tm time.Time, key *keys.EdX25519Key) (*http.Request, error) {
	return newRequest(context.TODO(), method, urs, body, contentHash, tm, keys.Rand32(), key)
}

// NewAuthRequestWithContext returns new authorized/signed HTTP request with context.
func NewAuthRequestWithContext(ctx context.Context, method string, urs string, body io.Reader, contentHash string, tm time.Time, key *keys.EdX25519Key) (*http.Request, error) {
	return newRequest(ctx, method, urs, body, contentHash, tm, keys.Rand32(), key)
}

func newRequest(ctx context.Context, method string, urs string, body io.Reader, contentHash string, tm time.Time, nonce *[32]byte, key *keys.EdX25519Key) (*http.Request, error) {
	auth, err := newAuth(method, urs, contentHash, tm, nonce, key)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, auth.URL.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth.Header())
	return req, nil
}
