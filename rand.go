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

// RandBase62 returns random base62.
func RandBase62(numBytes int) string {
	return encoding.MustEncode(RandBytes(numBytes), encoding.Base62)
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

// RandDigits returns string of random digits of length.
// RandDigits(6) => "745566"
func RandDigits(length int) string {
	charSet := numbers
	b := make([]byte, 0, length)
	for i := 0; i < length; i++ {
		b = append(b, randomChar(charSet, b))
	}
	return string(b)
}
