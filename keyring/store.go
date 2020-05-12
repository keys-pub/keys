package keyring

import (
	"crypto/subtle"
	"runtime"
	"time"

	"github.com/pkg/errors"
)

// Store is the cross platform keyring interface that a Keyring uses.
type Store interface {
	// Name of the Store implementation (keychain, wincred, secret-service, mem, fs).
	Name() string

	// Get bytes.
	Get(service string, id string) ([]byte, error)
	// Set bytes.
	Set(service string, id string, data []byte, typ string) error
	// Delete bytes.
	Delete(service string, id string) (bool, error)

	IDs(service string, opts *IDsOpts) ([]string, error)
	List(service string, key SecretKey, opts *ListOpts) ([]*Item, error)
	Exists(service string, id string) (bool, error)
	Reset(service string) error
}

// System returns system keyring store.
func System() Store {
	return system()
}

func defaultFS() Store {
	dir, err := defaultFSDir()
	if err != nil {
		panic(err)
	}
	fs, err := FS(dir)
	if err != nil {
		panic(err)
	}
	return fs
}

// SystemOrFS returns system keyring store or FS if unavailable.
// On linux, if dbus is not available, uses the filesystem at ~/.keyring.
func SystemOrFS() Store {
	if runtime.GOOS == "linux" {
		if err := checkSystem(); err != nil {
			logger.Infof("Keyring (system) unavailable: %v", err)
			return defaultFS()
		}
	}
	return system()
}

func getItem(st Store, service string, id string, key SecretKey) (*Item, error) {
	if key == nil {
		return nil, ErrLocked
	}
	b, err := st.Get(service, id)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, nil
	}
	return decodeItem(b, key)
}

const maxID = 254
const maxType = 32
const maxData = 2048

func setItem(st Store, service string, item *Item, key SecretKey) error {
	if key == nil {
		return ErrLocked
	}
	if len(item.ID) > maxID {
		return ErrItemValueTooLarge
	}
	if len(item.Type) > maxType {
		return ErrItemValueTooLarge
	}
	if len(item.Data) > maxData {
		return ErrItemValueTooLarge
	}

	data, err := item.Marshal(key)
	if err != nil {
		return err
	}
	// Max for windows credential blob
	if len(data) > (5 * 512) {
		return ErrItemValueTooLarge
	}
	return st.Set(service, item.ID, []byte(data), item.Type)
}

func decodeItem(b []byte, key SecretKey) (*Item, error) {
	if b == nil {
		return nil, nil
	}
	item, err := NewItemFromBytes(b, key)
	if err != nil {
		return nil, err
	}
	return item, nil
}

func unlock(st Store, service string, auth Auth) (SecretKey, error) {
	if auth == nil {
		return nil, errors.Errorf("no auth specified")
	}

	key := auth.Key()

	item, err := getItem(st, service, reserved("auth"), key)
	if err != nil {
		return nil, err
	}
	if item == nil {
		err := setItem(st, service, NewItem(reserved("auth"), key[:], "", time.Now()), key)
		if err != nil {
			return nil, err
		}
	} else {
		if subtle.ConstantTimeCompare(item.Data, key[:]) != 1 {
			return nil, errors.Errorf("invalid auth")
		}
	}

	return key, nil
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
