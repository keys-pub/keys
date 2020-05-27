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

// Auth ...
type Auth interface {
	// ID is an identifier for auth.
	ID() string
	// Key for auth.
	Key() SecretKey
}

type auth struct {
	id  string
	key SecretKey
}

func (k auth) Key() SecretKey {
	return k.key
}

func (k auth) ID() string {
	return k.id
}

// NewPasswordAuth generates a key from a password and salt.
func NewPasswordAuth(password string, salt []byte) (Auth, error) {
	if len(salt) < 16 {
		return nil, errors.Errorf("not enough salt")
	}
	if password == "" {
		return nil, errors.Errorf("empty password")
	}

	akey := argon2.IDKey([]byte(password), salt[:], 1, 64*1024, 4, 32)
	return &auth{
		id:  newAuthID(),
		key: bytes32(akey),
	}, nil
}

// NewAuth returns auth for key and type.
func NewAuth(id string, key SecretKey) Auth {
	return &auth{
		id:  id,
		key: key,
	}
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
