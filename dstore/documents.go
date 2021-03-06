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
	// To marshal a value, use dstore.From(v) to convert to a map (using msgpack or json tags).
	// If merging and using dstore.From(v), fields with omitempty will no overwrite existing values.
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

	// Set (or create or update) document at path.
	// This will overwrite any existing document data, unless you specify MergeAll() option.
	//
	// To marshal a value, use dstore.From(v) to convert to a map (using msgpack or json tags).
	// If merging and using dstore.From(v), fields with omitempty will no overwrite existing values.
	//
	// To update a document:
	//
	// 		update := map[string]interface{}{
	//		   "property1":        value1,
	// 		}
	// 		err := fi.Set(ctx, path, update, dstore.MergeAll())
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

	// Load path into value.
	// This is shorthand for Get and doc.To(&val).
	Load(ctx context.Context, path string, v interface{}) (bool, error)

	// GetAll at paths.
	// If a path is not found, it is ignored.
	GetAll(ctx context.Context, paths []string) ([]*Document, error)

	// Exists, if exists at path.
	Exists(ctx context.Context, path string) (bool, error)

	// Delete at path.
	Delete(ctx context.Context, path string) (bool, error)
	// DeleteAll paths. If a path is not found, it is ignored.
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

// Load path into value.
func Load(ctx context.Context, d Documents, path string, v interface{}) (bool, error) {
	doc, err := d.Get(ctx, path)
	if err != nil {
		return false, err
	}
	if doc == nil {
		return false, nil
	}
	if err := doc.To(v); err != nil {
		return false, err
	}
	return true, nil
}
