package keys

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDFSHA256 uses HKDF with SHA256.
// The `len` for output byte length.
// The `salt` is non-secret salt, optional (can be nil), recommended: hash-length random value.
// The `info` is non-secret context info, optional (can be empty).
func HKDFSHA256(secret []byte, len int, salt []byte, info []byte) []byte {
	hash := sha256.New
	hkdf := hkdf.New(hash, secret[:], salt, info)
	key := make([]byte, len)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}
