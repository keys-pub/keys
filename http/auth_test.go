package http

import (
	"bytes"
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	clock := tsutil.NewTestClock()

	tm := clock.Now()
	nonce := bytes.Repeat([]byte{0x01}, 32)
	urs := "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123"
	auth, err := newAuth("GET", urs, "", tm, nonce, alice)
	require.NoError(t, err)
	require.Equal(t, "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:K0KnYYnx+VnhpRS0lBJVfwSaYa3zweapGtc87Uh4h1pfv/VeVMaS/YRD/d+Y+U3ANFMkR+OFGRYniWirFK3sBg==", auth.Header())
	require.Equal(t, "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123&nonce=0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29&ts=1234567890001", auth.URL.String())

	req, err := newRequest("GET", urs, nil, "", tm, nonce, Authorization(alice))
	require.NoError(t, err)
	require.Equal(t, "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123&nonce=0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29&ts=1234567890001", req.URL.String())
	require.Equal(t, "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:K0KnYYnx+VnhpRS0lBJVfwSaYa3zweapGtc87Uh4h1pfv/VeVMaS/YRD/d+Y+U3ANFMkR+OFGRYniWirFK3sBg==", req.Header.Get("Authorization"))

	// Valid request
	mem := NewMem(tsutil.NewTestClock())
	_, err = Authorize(context.TODO(), &AuthRequest{
		Method:     "GET",
		URL:        "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123&nonce=0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29&ts=1234567890001",
		KID:        "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077",
		Auth:       "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:K0KnYYnx+VnhpRS0lBJVfwSaYa3zweapGtc87Uh4h1pfv/VeVMaS/YRD/d+Y+U3ANFMkR+OFGRYniWirFK3sBg==",
		Now:        clock.Now(),
		NonceCheck: mem.NonceCheck,
	})
	require.NoError(t, err)

	// Nonce collision (replay)
	_, err = Authorize(context.TODO(), &AuthRequest{
		Method:     "GET",
		URL:        "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123&nonce=0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29&ts=1234567890001",
		KID:        "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077",
		Auth:       "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:K0KnYYnx+VnhpRS0lBJVfwSaYa3zweapGtc87Uh4h1pfv/VeVMaS/YRD/d+Y+U3ANFMkR+OFGRYniWirFK3sBg==",
		Now:        clock.Now(),
		NonceCheck: mem.NonceCheck,
	})
	require.EqualError(t, err, "nonce collision")

	// Change method
	mem = NewMem(tsutil.NewTestClock())
	_, err = Authorize(context.TODO(), &AuthRequest{
		Method:     "HEAD",
		URL:        "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123&nonce=0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29&ts=1234567890001",
		KID:        "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077",
		Auth:       "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:K0KnYYnx+VnhpRS0lBJVfwSaYa3zweapGtc87Uh4h1pfv/VeVMaS/YRD/d+Y+U3ANFMkR+OFGRYniWirFK3sBg==",
		Now:        clock.Now(),
		NonceCheck: mem.NonceCheck,
	})
	require.EqualError(t, err, "verify failed")

	// Re-order url params
	mem = NewMem(tsutil.NewTestClock())
	_, err = Authorize(context.TODO(), &AuthRequest{
		Method:     "GET",
		URL:        "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?nonce=0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29&ts=1234567890001&idx=123",
		KID:        "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077",
		Auth:       "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:K0KnYYnx+VnhpRS0lBJVfwSaYa3zweapGtc87Uh4h1pfv/VeVMaS/YRD/d+Y+U3ANFMkR+OFGRYniWirFK3sBg==",
		Now:        clock.Now(),
		NonceCheck: mem.NonceCheck,
	})
	require.EqualError(t, err, "verify failed")

	// Different kid
	mem = NewMem(tsutil.NewTestClock())
	_, err = Authorize(context.TODO(), &AuthRequest{
		Method:     "GET",
		URL:        "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123&nonce=0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29&ts=1234567890001",
		KID:        "kex16jvh9cc6na54xwpjs3ztlxdsj6q3scl65lwxxj72m6cadewm404qts0jw9",
		Auth:       "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:K0KnYYnx+VnhpRS0lBJVfwSaYa3zweapGtc87Uh4h1pfv/VeVMaS/YRD/d+Y+U3ANFMkR+OFGRYniWirFK3sBg==",
		Now:        clock.Now(),
		NonceCheck: mem.NonceCheck,
	})
	require.EqualError(t, err, "invalid kid")

	// No nonce
	mem = NewMem(tsutil.NewTestClock())
	_, err = Authorize(context.TODO(), &AuthRequest{
		Method:     "GET",
		URL:        "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123&ts=1234567890001",
		KID:        "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077",
		Auth:       "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:MVMEa9LTK7LCVkNR3N2CwgXSPdoP2Vf+9F4NYcTzMpe+KbvaiUv73401isKJtgSGppoayJ5xY5uuT1xCE52rAA==",
		Now:        clock.Now(),
		NonceCheck: mem.NonceCheck,
	})
	require.EqualError(t, err, "nonce is missing")

	// No ts
	mem = NewMem(tsutil.NewTestClock())
	_, err = Authorize(context.TODO(), &AuthRequest{
		Method:     "GET",
		URL:        "https://keys.pub/vault/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077?idx=123&nonce=0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29",
		KID:        "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077",
		Auth:       "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077:vICq6ygK/KP2i/nsixrcIb+zDETPP1KoDdF3Pjs12EVH/xBAOZr5KwgmHHKrUxq3/AyyFJfgagYyCYdANoarAw==",
		Now:        clock.Now(),
		NonceCheck: mem.NonceCheck,
	})
	require.EqualError(t, err, "timestamp (ts) is missing")
}

func TestNewRequest(t *testing.T) {
	key := keys.GenerateEdX25519Key()
	clock := tsutil.NewTestClock()
	mem := NewMem(tsutil.NewTestClock())

	// GET
	req, err := NewAuthRequest("GET", "https://keys.pub/test", nil, "", clock.Now(), Authorization(key))
	require.NoError(t, err)
	check, err := Authorize(context.TODO(), &AuthRequest{
		Method:     "GET",
		URL:        req.URL.String(),
		KID:        key.ID(),
		Auth:       req.Header["Authorization"][0],
		Now:        clock.Now(),
		NonceCheck: mem.NonceCheck,
	})
	require.NoError(t, err)
	require.Equal(t, key.ID(), check.KID)

	// POST
	body := []byte(`{\"test\": 1}`)
	contentHash := ContentHash(body)
	req, err = NewAuthRequest("POST", "https://keys.pub/test", bytes.NewReader(body), contentHash, clock.Now(), Authorization(key))
	require.NoError(t, err)
	check, err = Authorize(context.TODO(), &AuthRequest{
		Method:      "POST",
		URL:         req.URL.String(),
		KID:         key.ID(),
		Auth:        req.Header["Authorization"][0],
		ContentHash: contentHash,
		Now:         clock.Now(),
		NonceCheck:  mem.NonceCheck,
	})
	require.NoError(t, err)
	require.Equal(t, key.ID(), check.KID)

	// POST (invalid content hash)
	req, err = NewAuthRequest("POST", "https://keys.pub/test", bytes.NewReader([]byte(body)), contentHash, clock.Now(), Authorization(key))
	require.NoError(t, err)
	_, err = Authorize(context.TODO(), &AuthRequest{
		Method:      "POST",
		URL:         req.URL.String(),
		KID:         key.ID(),
		Auth:        req.Header["Authorization"][0],
		ContentHash: ContentHash([]byte("invalid")),
		Now:         clock.Now(),
		NonceCheck:  mem.NonceCheck,
	})
	require.EqualError(t, err, "verify failed")
}
