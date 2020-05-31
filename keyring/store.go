package keyring

import (
	"runtime"
)

// Store is the interface that a Keyring uses to save data.
type Store interface {
	// Name of the Store implementation (keychain, wincred, secret-service, mem, fs, git).
	Name() string

	// Get bytes.
	Get(service string, id string) ([]byte, error)
	// Set bytes.
	Set(service string, id string, data []byte) error
	// Delete bytes.
	Delete(service string, id string) (bool, error)

	// List IDs.
	IDs(service string, opts ...IDsOption) ([]string, error)

	// Exists returns true if exists.
	Exists(service string, id string) (bool, error)

	// Reset removes all items.
	Reset(service string) error
}

// System returns system keyring store.
func System() Store {
	return system()
}

func defaultLinuxFS() Store {
	dir, err := defaultLinuxFSDir()
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
			return defaultLinuxFS()
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
	return decryptItem(b, key)
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
	return st.Set(service, item.ID, []byte(data))
}

func decryptItem(b []byte, key SecretKey) (*Item, error) {
	if b == nil {
		return nil, nil
	}
	item, err := DecryptItem(b, key)
	if err != nil {
		return nil, err
	}
	return item, nil
}
