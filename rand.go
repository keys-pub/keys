package keys

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/keys-pub/keys/encoding"
)

// RandBytes returns random bytes of length.
func RandBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// RandPhrase creates random phrase (BIP39 encoded random 32 bytes).
func RandPhrase() string {
	b := RandBytes(32)
	phrase, err := encoding.BytesToPhrase(b)
	if err != nil {
		panic(err)
	}
	return phrase
}

// RandWords returns random (BIP39) words.
// numWords must be 1 to 24.
func RandWords(numWords int) string {
	if numWords <= 0 || numWords > 24 {
		panic("invalid number of words specified")
	}
	words := strings.Split(RandPhrase(), " ")
	return strings.Join(words[:numWords], " ")
}

// Rand16 generates random 16 bytes.
func Rand16() *[16]byte {
	b := RandBytes(16)
	var b16 [16]byte
	copy(b16[:], b[:16])
	return &b16
}

// Rand24 generates random 24 bytes.
func Rand24() *[24]byte {
	b := RandBytes(24)
	var b24 [24]byte
	copy(b24[:], b[:24])
	return &b24
}

// Rand32 generates random 32 bytes.
func Rand32() *[32]byte {
	b := RandBytes(32)
	var b32 [32]byte
	copy(b32[:], b[:32])
	return &b32
}

// RandUsername returns random lowercase string of length.
func RandUsername(length int) string {
	r := []rune{}
	for i := 0; i < length; i++ {
		rn, err := rand.Int(rand.Reader, big.NewInt(26))
		if err != nil {
			panic(err)
		}
		n := rn.Int64() + 0x61 // 0x61 == "a"
		r = append(r, rune(n))
	}
	return string(r)
}

// RandHex returns random hex.
func RandHex(numBytes int) string {
	return hex.EncodeToString(RandBytes(numBytes))
}

// RandTempPath returns a unique random file name in os.TempDir.
// RandTempPath() => "/tmp/CTGMMOLLZCXMGP7VR4BHKAI7PE"
func RandTempPath() string {
	return filepath.Join(os.TempDir(), RandFileName())
}

// RandFileName returns a unique random file name.
// RandFileName() => CTGMMOLLZCXMGP7VR4BHKAI7PE
func RandFileName() string {
	return encoding.MustEncode(RandBytes(16), encoding.Base32, encoding.NoPadding())
}

// Bytes64 converts byte slice to *[64]byte.
func Bytes64(b []byte) *[64]byte {
	if len(b) != 64 {
		panic("not 64 bytes")
	}
	var b64 [64]byte
	copy(b64[:], b)
	return &b64
}

// Bytes32 converts byte slice to *[32]byte.
func Bytes32(b []byte) *[32]byte {
	if len(b) != 32 {
		panic("not 32 bytes")
	}
	var b32 [32]byte
	copy(b32[:], b)
	return &b32
}

// Bytes24 converts byte slice to *[24]byte.
func Bytes24(b []byte) *[24]byte {
	if len(b) != 24 {
		panic("not 24 bytes")
	}
	var b24 [24]byte
	copy(b24[:], b)
	return &b24
}

// Bytes16 converts byte slice to *[16]byte.
func Bytes16(b []byte) *[16]byte {
	if len(b) != 16 {
		panic("not 16 bytes")
	}
	var b16 [16]byte
	copy(b16[:], b)
	return &b16
}
