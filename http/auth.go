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

// AuthResult is the authorized result.
type AuthResult struct {
	KID       keys.ID
	Method    string
	URL       *url.URL
	Nonce     string
	Timestamp time.Time
}

// CheckAuthorization checks request authorization.
func CheckAuthorization(ctx context.Context, method string, urs string, kid keys.ID, auth string, contentHash string, nonces Nonces, now time.Time) (*AuthResult, error) {
	res, err := CheckAuthorizations(ctx, method, urs, []keys.ID{kid}, []string{auth}, contentHash, nonces, now)
	if err != nil {
		return nil, err
	}
	if len(res) != 1 {
		return nil, errors.Errorf("invalid auth results")
	}
	return res[0], nil
}

// CheckAuthorizations checks (multiple) request authorizations.
// A request may include multiple authorizations with a single nonce and timestamp.
func CheckAuthorizations(ctx context.Context, method string, urs string, kids []keys.ID, auths []string, contentHash string, nonces Nonces, now time.Time) ([]*AuthResult, error) {
	if len(kids) != len(auths) {
		return nil, errors.Errorf("kid/auth length mismatch")
	}
	url, err := url.Parse(urs)
	if err != nil {
		return nil, err
	}
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
	tm := tsutil.ConvertMillis(i)
	td := now.Sub(tm)
	if td < 0 {
		td = td * -1
	}
	if td > 30*time.Minute {
		return nil, errors.Errorf("timestamp is invalid, diff %s", td)
	}

	results := []*AuthResult{}
	for i := 0; i < len(kids); i++ {
		kid := kids[i]
		auth := auths[i]

		fields := strings.Split(auth, ":")
		if len(fields) != 2 {
			return nil, errors.Errorf("too many fields")
		}
		hkid := fields[0]
		hsig := fields[1]

		akid, err := keys.ParseID(hkid)
		if err != nil {
			return nil, err
		}
		if kid != "" && akid != kid {
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

		bytesToSign := method + "," + url.String() + "," + contentHash
		if err := spk.VerifyDetached(sigBytes, []byte(bytesToSign)); err != nil {
			return nil, err
		}
		results = append(results, &AuthResult{
			KID:       akid,
			Method:    method,
			URL:       url,
			Nonce:     nonce,
			Timestamp: tm,
		})
	}

	val, err := nonces.Get(ctx, nonce)
	if err != nil {
		return nil, err
	}
	if val != "" {
		return nil, errors.Errorf("nonce collision")
	}
	if err := nonces.Set(ctx, nonce, "1"); err != nil {
		return nil, err
	}
	if err := nonces.Expire(ctx, nonce, time.Hour); err != nil {
		return nil, err
	}

	return results, nil
}
