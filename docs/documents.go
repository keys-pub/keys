package docs

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
	Create(ctx context.Context, path string, fields []Field) error

	// Set (or create) document at path.
	//
	// Paths can be nested as long as they are even length components.
	// For example,
	//
	//   collection1/key1 (OK)
	//   collection1/key1/collection2/key2 (OK)
	//   collection1 (INVALID)
	//   collection1/key1/collection2 (INVALID)
	//
	Set(ctx context.Context, path string, fields []Field) error

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

// Field in document.
type Field struct {
	Name  string
	Value interface{}
}

// NewFields from map.
func NewFields(mp ...interface{}) []Field {
	fields := []Field{}
	if len(mp)%2 != 0 {
		panic("invalid fields")
	}
	for i := 0; i < len(mp); i += 2 {
		k, v := mp[i], mp[i+1]
		fields = append(fields, NewField(k.(string), v))
	}
	return fields
}

// NewField ..
func NewField(name string, v interface{}) Field {
	return Field{Name: name, Value: v}
}

// Data as document fields.
func Data(b []byte) []Field {
	return NewFields("data", b)
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
