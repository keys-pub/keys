package keys

import (
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
