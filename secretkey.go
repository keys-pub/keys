package keys

import "github.com/pkg/errors"

// SecretKeySize is the size of nacl.secretbox key bytes.
const SecretKeySize = 32

// SecretKey is a symmetric key compatible with nacl.secretbox.
type SecretKey *[SecretKeySize]byte

// NewSecretKey from bytes.
func NewSecretKey(b []byte) (SecretKey, error) {
	if l := len(b); l != SecretKeySize {
		return nil, errors.Errorf("secret key byte len %d != %d", l, SecretKeySize)
	}
	var k [SecretKeySize]byte
	copy(k[:], b[:SecretKeySize])
	return &k, nil
}

// GenerateSecretKey generates a SecretKey.
func GenerateSecretKey() SecretKey {
	logger.Infof("Generating secret key...")
	return RandKey()
}
