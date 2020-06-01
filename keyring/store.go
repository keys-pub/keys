package keyring

import (
	"runtime"
)

// Store is the interface that a Keyring uses to save data.
type Store interface {
	// Name of the Store implementation (keychain, wincred, secret-service, mem, fs, git).
	Name() string

	// Get bytes.
	Get(id string) ([]byte, error)
	// Set bytes.
	Set(id string, data []byte) error
	// Delete bytes.
	Delete(id string) (bool, error)

	// List IDs.
	IDs(opts ...IDsOption) ([]string, error)

	// Exists returns true if exists.
	Exists(id string) (bool, error)

	// Reset removes all items.
	Reset() error
}

// WithStore specifies Store to use with Keyring.
func WithStore(st Store) Option {
	return func(o *Options) error {
		o.st = st
		return nil
	}
}

// System Store option.
func System(service string) Option {
	return func(o *Options) error {
		st := NewSystem(service)
		o.st = st
		return nil
	}
}

// NewSystem creates system Store.
func NewSystem(service string) Store {
	return system(service)
}

func defaultLinuxFS(service string) (Store, error) {
	dir, err := defaultLinuxFSDir()
	if err != nil {
		return nil, err
	}
	fs, err := NewFS(service, dir)
	if err != nil {
		return nil, err
	}
	return fs, nil
}

// SystemOrFS Store option.
func SystemOrFS(service string) Option {
	return func(o *Options) error {
		st, err := NewSystemOrFS(service)
		if err != nil {
			return err
		}
		o.st = st
		return nil
	}
}

// NewSystemOrFS returns system keyring store or FS if unavailable.
// On linux, if dbus is not available, uses the filesystem at ~/.keyring.
func NewSystemOrFS(service string) (Store, error) {
	if runtime.GOOS == "linux" {
		if err := checkSystem(); err != nil {
			logger.Infof("Keyring (system) unavailable: %v", err)
			return defaultLinuxFS(service)
		}
	}
	return system(service), nil
}

func getItem(st Store, id string, key SecretKey) (*Item, error) {
	if key == nil {
		return nil, ErrLocked
	}
	b, err := st.Get(id)
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

func setItem(st Store, item *Item, key SecretKey) error {
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
	return st.Set(item.ID, []byte(data))
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
