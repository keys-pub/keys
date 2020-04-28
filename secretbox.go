package keys

import (
	"bytes"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

// SecretBoxSeal encrypts using a key.
// It prepends a 24 byte nonce to the the encrypted bytes.
func SecretBoxSeal(b []byte, secretKey *[32]byte) []byte {
	nonce := Rand24()
	return sealSecretBox(b, nonce, secretKey)
}

func sealSecretBox(b []byte, nonce *[24]byte, secretKey *[32]byte) []byte {
	encrypted := secretbox.Seal(nil, b, nonce, secretKey)
	encrypted = append(nonce[:], encrypted...)
	return encrypted
}

// SecretBoxOpen decrypt using a key.
// It assumes a 24 byte nonce before the encrypted bytes.
func SecretBoxOpen(encrypted []byte, secretKey *[32]byte) ([]byte, error) {
	return openSecretBox(encrypted, secretKey)
}

func openSecretBox(encrypted []byte, secretKey *[32]byte) ([]byte, error) {
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

// EncryptWithPassword encrypts bytes with a password.
// Uses argon2.IDKey(password, salt, 1, 64*1024, 4, 32) with 16 byte salt.
// The salt bytes are prepended to the encrypted bytes.
func EncryptWithPassword(b []byte, password string) []byte {
	salt := Rand16()
	key := argon2.IDKey([]byte(password), salt[:], 1, 64*1024, 4, 32)
	encrypted := SecretBoxSeal(b, Bytes32(key))
	return bytesJoin(salt[:], encrypted)
}

// DecryptWithPassword decrypts bytes using a password.
// It assumes a 16 byte salt before the encrypted bytes.
func DecryptWithPassword(encrypted []byte, password string) ([]byte, error) {
	if len(encrypted) < 16 {
		return nil, errors.Errorf("failed to decrypt with a password: not enough bytes")
	}
	salt := encrypted[0:16]
	b := encrypted[16:]
	key := argon2.IDKey([]byte(password), salt[:], 1, 64*1024, 4, 32)
	out, err := SecretBoxOpen(b, Bytes32(key))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decrypt with a password")
	}
	return out, nil
}

func bytesJoin(b ...[]byte) []byte {
	return bytes.Join(b, []byte{})
}
