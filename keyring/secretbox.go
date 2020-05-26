package keyring

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/secretbox"
)

// SecretKey for encrypting items.
type SecretKey *[32]byte

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func rand24() *[24]byte {
	b := randBytes(24)
	var b24 [24]byte
	copy(b24[:], b[:24])
	return &b24
}

func rand32() *[32]byte {
	b := randBytes(32)
	var b32 [32]byte
	copy(b32[:], b[:32])
	return &b32
}

func bytes32(b []byte) *[32]byte {
	if len(b) != 32 {
		panic("not 32 bytes")
	}
	var b32 [32]byte
	copy(b32[:], b)
	return &b32
}

func secretBoxSeal(b []byte, secretKey SecretKey) []byte {
	nonce := rand24()
	encrypted := secretbox.Seal(nil, b, nonce, secretKey)
	encrypted = append(nonce[:], encrypted...)
	return encrypted
}

func secretBoxOpen(encrypted []byte, secretKey SecretKey) ([]byte, bool) {
	if secretKey == nil {
		return nil, false
	}
	if len(encrypted) < 24 {
		return nil, false
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	encrypted = encrypted[24:]

	return secretbox.Open(nil, encrypted, &nonce, secretKey)
}
