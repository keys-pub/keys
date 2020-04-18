package keyring

import (
	"fmt"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// ErrInvalidAuth if auth is invalid.
var ErrInvalidAuth = errors.New("invalid keyring auth")

// ErrLocked if no keyring key is set.
var ErrLocked = errors.New("keyring is locked")

// Auth ...
type Auth interface {
	Name() string
	Key() SecretKey
}

type keyAuth struct {
	name string
	key  SecretKey
}

func (k keyAuth) Name() string {
	return k.name
}

func (k keyAuth) Key() SecretKey {
	return k.key
}

// NewPasswordAuth generates key from password, salt and secret key.
func NewPasswordAuth(name string, password string, salt []byte) (Auth, error) {
	if len(salt) < 16 {
		return nil, errors.Errorf("not enough salt")
	}
	if password == "" {
		return nil, errors.Errorf("no password")
	}

	akey := argon2.IDKey([]byte(password), salt[:], 1, 64*1024, 4, 32)
	return &keyAuth{
		name: name,
		key:  bytes32(akey),
	}, nil
}

// NewKeyAuth returns auth with a key.
func NewKeyAuth(name string, key SecretKey) Auth {
	return &keyAuth{
		name: name,
		key:  key,
	}
}

func authSetup(st Store, service string, auth Auth) (SecretKey, error) {
	mk := rand32()
	if err := authProvision(st, service, auth, mk); err != nil {
		return nil, err
	}
	return mk, nil
}

func authID(auth Auth) (string, error) {
	name := auth.Name()
	if name == "" {
		return "", errors.Errorf("no auth name")
	}
	if !encoding.IsASCII([]byte(name)) || len(name) > 32 {
		return "", errors.Errorf("invalid auth name")
	}
	return reserved(fmt.Sprintf("auth-%s", name)), nil
}

func authProvision(st Store, service string, auth Auth, mk SecretKey) error {
	if mk == nil {
		return errors.Errorf("no key for provisioning")
	}
	id, err := authID(auth)
	if err != nil {
		return err
	}
	logger.Debugf("Provisioning %s", id)
	item := NewItem(id, mk[:], "", time.Now())
	if err := setItem(st, service, item, auth.Key()); err != nil {
		return err
	}
	return nil
}

func authDeprovision(st Store, service string, auth Auth) (bool, error) {
	id, err := authID(auth)
	if err != nil {
		return false, err
	}
	logger.Debugf("Deprovisioning %s", id)
	ok, err := st.Delete(service, id)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func authUnlock(st Store, service string, auth Auth) (SecretKey, error) {
	if auth == nil {
		return nil, errors.Errorf("no auth specified")
	}
	id, err := authID(auth)
	if err != nil {
		return nil, err
	}
	logger.Debugf("Unlocking %s", id)
	item, err := getItem(st, service, id, auth.Key())
	if err != nil {
		return nil, err
	}
	if item == nil {
		// Check for original auth key "#auth".
		// Remove this in the future (04/17/2020).
		item, err = getItem(st, service, "#auth", auth.Key())
		if err != nil {
			return nil, err
		}
		if item == nil {
			return nil, ErrInvalidAuth
		}
	}
	if len(item.Data) != 32 {
		return nil, errors.Errorf("invalid auth key value")
	}
	return bytes32(item.Data), nil
}

func salt(st Store, service string) ([]byte, error) {
	salt, err := st.Get(service, reserved("salt"))
	if err != nil {
		return nil, err
	}
	if salt == nil {
		salt = rand32()[:]
		if err := st.Set(service, reserved("salt"), salt, ""); err != nil {
			return nil, err
		}
	}
	return salt, nil
}
