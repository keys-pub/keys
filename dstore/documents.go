package dstore

import (
	"context"
	"fmt"
)

// Documents describes a Document store.
type Documents interface {
	// Create document at path.
	// ErrPathExists if path already exists.
	//
	// Paths can be nested as long as they are even length components.
	// For example,
	//
	//   collection1/key1 (OK)
	//   collection1/key1/collection2/key2 (OK)
	//   collection1 (INVALID)
	//   collection1/key1/collection2 (INVALID)
	//
	Create(ctx context.Context, path string, values map[string]interface{}) error

	// Set (or create) document at path.
	// This will overwrite any existing document data.
	//
	// Paths can be nested as long as they are even length components.
	// For example,
	//
	//   collection1/key1 (OK)
	//   collection1/key1/collection2/key2 (OK)
	//   collection1 (INVALID)
	//   collection1/key1/collection2 (INVALID)
	//
	Set(ctx context.Context, path string, values map[string]interface{}, opt ...SetOption) error

	// Get path.
	// If not found, returns nil.
	Get(ctx context.Context, path string) (*Document, error)

	// GetAll at paths.
	// If a path is not found, it is ignored.
	GetAll(ctx context.Context, paths []string) ([]*Document, error)

	// Exists, if exists at path.
	Exists(ctx context.Context, path string) (bool, error)

	// Delete at path.
	Delete(ctx context.Context, path string) (bool, error)
	// If a path is not found, it is ignored.
	DeleteAll(ctx context.Context, paths []string) error

	// DocumentIterator.
	DocumentIterator(ctx context.Context, parent string, opt ...Option) (Iterator, error)

	// Documents ...
	Documents(ctx context.Context, parent string, opt ...Option) ([]*Document, error)

	// Collections are parents of Documents.
	Collections(ctx context.Context, parent string) ([]*Collection, error)
}

// Data as document fields.
func Data(b []byte) map[string]interface{} {
	return map[string]interface{}{
		"data": b,
	}
}

// ErrPathExists is trying to set value that already exists.
type ErrPathExists struct {
	Path string
}

func (e ErrPathExists) Error() string {
	return fmt.Sprintf("path already exists %s", e.Path)
}

// NewErrPathExists ...
func NewErrPathExists(path string) ErrPathExists {
	return ErrPathExists{Path: path}
}

// ErrNotFound if path not found.
type ErrNotFound struct {
	Path string
}

func (e ErrNotFound) Error() string {
	return fmt.Sprintf("path not found %s", e.Path)
}

// NewErrNotFound ...
func NewErrNotFound(path string) ErrNotFound {
	return ErrNotFound{Path: path}
}
