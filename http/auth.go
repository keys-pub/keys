package http

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

// Auth describes auth for an HTTP request.
type Auth struct {
	KID         keys.ID
	Method      string
	URL         *url.URL
	Sig         string
	BytesToSign string
}

// Header is header value.
func (a Auth) Header() string {
	return a.KID.String() + ":" + a.Sig
}

// NewAuth returns auth for an HTTP request.
// The url shouldn't have ? or &.
func NewAuth(method string, urs string, contentHash string, tm time.Time, key *keys.EdX25519Key) (*Auth, error) {
	ur, err := authURL(urs, tm, keys.RandBytes(20))
	if err != nil {
		return nil, err
	}
	return newAuthWithURL(method, ur, contentHash, key)
}

// ContentHash returns base64 encoded sha256 hash.
func ContentHash(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := sha256.Sum256(b)
	return encoding.EncodeBase64(h[:])
}

func authURL(urs string, tm time.Time, nonce []byte) (*url.URL, error) {
	if len(nonce) < 16 {
		return nil, errors.Errorf("invalid nonce")
	}
	ur, err := url.Parse(urs)
	if err != nil {
		return nil, err
	}
	q := ur.Query()
	ns := encoding.MustEncode(nonce, encoding.Base62)
	q.Set("nonce", ns)
	ts := tsutil.Millis(tm)
	q.Set("ts", fmt.Sprintf("%d", ts))
	ur.RawQuery = q.Encode()
	return ur, nil
}

func newAuth(method string, urs string, contentHash string, tm time.Time, nonce []byte, key *keys.EdX25519Key) (*Auth, error) {
	ur, err := authURL(urs, tm, nonce)
	if err != nil {
		return nil, err
	}
	return newAuthWithURL(method, ur, contentHash, key)
}

func newAuthWithURL(method string, ur *url.URL, contentHash string, key *keys.EdX25519Key) (*Auth, error) {
	bytesToSign := method + "," + ur.String() + "," + contentHash
	sb := key.SignDetached([]byte(bytesToSign))
	sig := encoding.EncodeBase64(sb)
	return &Auth{KID: key.ID(), Method: method, URL: ur, Sig: sig, BytesToSign: bytesToSign}, nil
}

// AuthRequest describes an auth request.
type AuthRequest struct {
	Method      string
	URL         string
	ContentHash string

	KID  keys.ID
	Auth string

	Now        time.Time
	NonceCheck NonceCheck
}

// AuthResult is the result of an auth check.
type AuthResult struct {
	KID       keys.ID
	URL       *url.URL
	Nonce     string
	Timestamp time.Time
}

// NonceCheck checks for nonce.
type NonceCheck func(ctx context.Context, nonce string) error

// Authorize checks request authorization.
// Nonce check should fail if there is a collision across different requests.
func Authorize(ctx context.Context, auth *AuthRequest) (*AuthResult, error) {
	url, err := url.Parse(auth.URL)
	if err != nil {
		return nil, err
	}
	if url.String() != auth.URL {
		return nil, errors.Errorf("invalid url parse")
	}

	// Parse nonce
	nonce := url.Query().Get("nonce")
	if nonce == "" {
		return nil, errors.Errorf("nonce is missing")
	}
	nb, err := encoding.Decode(nonce, encoding.Base62)
	if err != nil {
		return nil, err
	}
	if len(nb) < 16 {
		return nil, errors.Errorf("nonce is invalid length")
	}

	// Check timestamp
	ts := url.Query().Get("ts")
	if ts == "" {
		return nil, errors.Errorf("timestamp (ts) is missing")
	}
	i, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, err
	}
	tm := tsutil.ParseMillis(i)
	td := auth.Now.Sub(tm)
	if td < 0 {
		td = td * -1
	}
	if td > 30*time.Minute {
		return nil, errors.Errorf("timestamp is invalid, diff %s", td)
	}

	fields := strings.Split(auth.Auth, ":")
	if len(fields) != 2 {
		return nil, errors.Errorf("too many fields")
	}
	hkid := fields[0]
	hsig := fields[1]

	akid, err := keys.ParseID(hkid)
	if err != nil {
		return nil, err
	}
	if auth.KID != "" && akid != auth.KID {
		return nil, errors.Errorf("invalid kid")
	}

	spk, err := keys.StatementPublicKeyFromID(akid)
	if err != nil {
		return nil, errors.Errorf("not a valid sign public key")
	}

	sigBytes, err := encoding.Decode(hsig, encoding.Base64)
	if err != nil {
		return nil, err
	}

	bytesToSign := auth.Method + "," + url.String() + "," + auth.ContentHash
	if err := spk.VerifyDetached(sigBytes, []byte(bytesToSign)); err != nil {
		return nil, err
	}

	if auth.NonceCheck == nil {
		return nil, errors.Errorf("no nonce check")
	}

	if err := auth.NonceCheck(ctx, nonce); err != nil {
		return nil, err
	}

	return &AuthResult{
		KID:       akid,
		URL:       url,
		Nonce:     nonce,
		Timestamp: tm,
	}, nil
}

// if err := nonces.Set(ctx, nonce, "1"); err != nil {
// 	return nil, err
// }
// if err := nonces.Expire(ctx, nonce, time.Hour); err != nil {
// 	return nil, err
// }
