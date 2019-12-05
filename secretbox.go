package keys

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

// SecretBoxSeal encrypt using SecretKey.
func SecretBoxSeal(b []byte, secretKey SecretKey) []byte {
	nonce := Rand24()
	return sealSecretBox(b, nonce, secretKey)
}

func sealSecretBox(b []byte, nonce *[24]byte, secretKey SecretKey) []byte {
	encrypted := secretbox.Seal(nil, b, nonce, secretKey)
	encrypted = append(nonce[:], encrypted...)
	return encrypted
}

// SecretBoxOpen decrypt using SecretKey.
func SecretBoxOpen(encrypted []byte, secretKey SecretKey) ([]byte, error) {
	return openSecretBox(encrypted, secretKey)
}

func openSecretBox(encrypted []byte, secretKey SecretKey) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, errors.Errorf("not enough bytes")
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	encrypted = encrypted[24:]

	b, ok := secretbox.Open(nil, encrypted, &nonce, secretKey)
	if !ok {
		return nil, errors.Errorf("secretbox open failed")
	}
	return b, nil
}
