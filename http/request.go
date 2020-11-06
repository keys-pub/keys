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

// NewAuthRequest returns new authorized/signed HTTP request.
func NewAuthRequest(method string, urs string, body io.Reader, contentHash string, tm time.Time, key *keys.EdX25519Key) (*http.Request, error) {
	return newRequest(method, urs, body, contentHash, tm, keys.RandBytes(24), []*AuthKey{&AuthKey{Key: key, Header: "Authorization"}})
}

// NewMultiAuthRequest returns new authorized/signed HTTP request from multiple keys.
func NewMultiAuthRequest(method string, urs string, body io.Reader, contentHash string, tm time.Time, aks []*AuthKey) (*http.Request, error) {
	return newRequest(method, urs, body, contentHash, tm, keys.RandBytes(24), aks)
}

func newRequest(method string, urs string, body io.Reader, contentHash string, tm time.Time, nonce []byte, aks []*AuthKey) (*http.Request, error) {
	ur, err := authURL(urs, tm, nonce)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, ur.String(), body)
	if err != nil {
		return nil, err
	}
	for _, ak := range aks {
		auth, err := newAuthWithURL(method, ur, contentHash, ak.Key)
		if err != nil {
			return nil, err
		}
		req.Header.Set(ak.Header, auth.Header())
	}
	return req, nil
}

// NewAuthKey creates an AuthKey.
func NewAuthKey(header string, key *keys.EdX25519Key) *AuthKey {
	return &AuthKey{Key: key, Header: header}
}

// AuthKey ...
type AuthKey struct {
	Key    *keys.EdX25519Key
	Header string
}
