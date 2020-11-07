// Package keyring provides a cross-platform secure keyring.
package keyring

import (
	"github.com/pkg/errors"
)

// NewSystem creates system keyring.
func NewSystem(service string) (Keyring, error) {
	if service == "" {
		return nil, errors.Errorf("invalid service")
	}
	return newSystem(service), nil
}

// Item ..
type Item struct {
	ID   string
	Data []byte
}

// Keyring is the interface used to store data.
type Keyring interface {
	// Name of the keyring implementation.
	Name() string

	// Get bytes.
	Get(id string) ([]byte, error)
	// Set bytes.
	Set(id string, data []byte) error
	// Delete bytes.
	Delete(id string) (bool, error)

	// Exists returns true if exists.
	Exists(id string) (bool, error)

	// Reset removes all data.
	Reset() error

	Items(prefix string) ([]*Item, error)
}

// IDs from Keyring.
func IDs(kr Keyring, prefix string) ([]string, error) {
	items, err := kr.Items(prefix)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	for _, item := range items {
		paths = append(paths, item.ID)
	}
	return paths, nil
}

var _ = reset

func reset(kr Keyring) error {
	ids, err := IDs(kr, "")
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := kr.Delete(id); err != nil {
			return err
		}
	}
	return nil
}
