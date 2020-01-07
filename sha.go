package keys

import (
	"crypto/hmac"
	"crypto/sha256"
)

// SHA256 for bytes.
func SHA256(b []byte) []byte {
	if len(b) == 0 {
		panic("empty bytes")
	}
	h := sha256.New()
	if _, err := h.Write(b); err != nil {
		panic(err)
	}
	bs := h.Sum(nil)
	if len(bs) == 0 {
		panic("empty bytes for sum")
	}
	return bs
}

// HMACSHA256 does a HMAC-SHA256 on msg with key.
func HMACSHA256(key []byte, msg []byte) []byte {
	if len(key) == 0 {
		panic("empty hmac key")
	}
	if len(msg) == 0 {
		panic("empty hmac msg")
	}
	h := hmac.New(sha256.New, key)
	n, err := h.Write(msg)
	if err != nil {
		panic(err)
	}
	if n != len(msg) {
		panic("failed to write all bytes")
	}
	out := h.Sum(nil)
	if len(out) == 0 {
		panic("empty bytes")
	}
	return out
}
