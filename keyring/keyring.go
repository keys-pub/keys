// Package keyring provides a cross-platform secure keyring.
package keyring

import (
	"github.com/keys-pub/keys/ds"
	"github.com/pkg/errors"
)

// NewSystem creates system keyring.
func NewSystem(service string) (Keyring, error) {
	if service == "" {
		return nil, errors.Errorf("invalid service")
	}
	return newSystem(service), nil
}

// Keyring is the interface used to store data.
// This can be used as a vault.Store.
type Keyring interface {
	// Name of the Store implementation.
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

	Documents(opt ...ds.DocumentsOption) (ds.DocumentIterator, error)
}

// Paths from Keyring.
func Paths(kr Keyring, prefix string) ([]string, error) {
	iter, err := kr.Documents(ds.Prefix(prefix), ds.NoData())
	if err != nil {
		return nil, err
	}
	defer iter.Release()
	paths := []string{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		paths = append(paths, doc.Path)
	}
	return paths, nil
}

// Documents from Keyring.
func Documents(kr Keyring, prefix string) ([]*ds.Document, error) {
	iter, err := kr.Documents(ds.Prefix(prefix))
	if err != nil {
		return nil, err
	}
	defer iter.Release()
	docs := []*ds.Document{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}

		docs = append(docs, &ds.Document{Path: doc.Path, Data: copyBytes(doc.Data)})
	}
	return docs, nil
}

var _ = reset

func reset(kr Keyring) error {
	paths, err := Paths(kr, "")
	if err != nil {
		return err
	}
	for _, p := range paths {
		if _, err := kr.Delete(p); err != nil {
			return err
		}
	}
	return nil
}

func copyBytes(source []byte) []byte {
	dest := make([]byte, len(source))
	copy(dest, source)
	return dest
}
