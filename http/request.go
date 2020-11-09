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

// AuthProvider provides auth keys for Authorization.
type AuthProvider interface {
	Keys() []*AuthKey
}

// NewAuthRequest returns new authorized/signed HTTP request from keys.
func NewAuthRequest(method string, urs string, body io.Reader, contentHash string, tm time.Time, auth AuthProvider) (*http.Request, error) {
	return newRequest(method, urs, body, contentHash, tm, keys.RandBytes(24), auth)
}

func newRequest(method string, urs string, body io.Reader, contentHash string, tm time.Time, nonce []byte, auth AuthProvider) (*http.Request, error) {
	ur, err := authURL(urs, tm, nonce)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, ur.String(), body)
	if err != nil {
		return nil, err
	}
	for _, ak := range auth.Keys() {
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

// Authorization creates a default authorization with a EdX25519 key.
func Authorization(key *keys.EdX25519Key) AuthProvider {
	return authProvider{[]*AuthKey{NewAuthKey("Authorization", key)}}
}

// AuthKeys creates a Authorization from AuthKey's.
func AuthKeys(aks ...*AuthKey) AuthProvider {
	return authProvider{aks}
}

type authProvider struct {
	aks []*AuthKey
}

func (a authProvider) Keys() []*AuthKey {
	return a.aks
}

// AuthKey ...
type AuthKey struct {
	Key    *keys.EdX25519Key
	Header string
}
