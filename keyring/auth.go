package keyring

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// ErrInvalidAuth if auth is invalid.
var ErrInvalidAuth = errors.New("invalid keyring auth")

// ErrLocked if no keyring key is set.
var ErrLocked = errors.New("keyring is locked")

// Auth ...
type Auth interface {
	Key() SecretKey
}

type keyAuth struct {
	key SecretKey
}

func (k keyAuth) Key() SecretKey {
	return k.key
}

// NewPasswordAuth generates a key from a password and salt.
func NewPasswordAuth(password string, salt []byte) (Auth, error) {
	if len(salt) < 16 {
		return nil, errors.Errorf("not enough salt")
	}

	akey := argon2.IDKey([]byte(password), salt[:], 1, 64*1024, 4, 32)
	return &keyAuth{
		key: bytes32(akey),
	}, nil
}

// NewKeyAuth returns auth with a key.
func NewKeyAuth(key SecretKey) Auth {
	return &keyAuth{
		key: key,
	}
}
