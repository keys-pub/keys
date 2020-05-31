package keyring

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// ErrInvalidAuth if auth is invalid.
var ErrInvalidAuth = errors.New("invalid keyring auth")

// ErrLocked if no keyring key is set.
var ErrLocked = errors.New("keyring is locked")

// ErrAlreadySetup if already setup.
var ErrAlreadySetup = errors.New("keyring is already setup")

// KeyForPassword generates a key from a password and salt.
func KeyForPassword(password string, salt []byte) (SecretKey, error) {
	if len(salt) < 16 {
		return nil, errors.Errorf("not enough salt")
	}
	if password == "" {
		return nil, errors.Errorf("empty password")
	}

	akey := argon2.IDKey([]byte(password), salt[:], 1, 64*1024, 4, 32)
	return bytes32(akey), nil
}

// Salt is default salt value, generated on first access and persisted
// until Reset().
// This salt value is not encrypted in the keyring.
// Doesn't require Unlock().
func (k *Keyring) Salt() ([]byte, error) {
	return salt(k.st, k.service)
}

// salt returns a salt value, generating it on first access if it doesn't exist.
func salt(st Store, service string) ([]byte, error) {
	salt, err := st.Get(service, reserved("salt"))
	if err != nil {
		return nil, err
	}
	if salt == nil {
		salt = rand32()[:]
		if err := st.Set(service, reserved("salt"), salt); err != nil {
			return nil, err
		}
	}
	return salt, nil
}
