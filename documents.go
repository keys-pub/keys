package keys

import (
	"context"
	"fmt"
)

// DocumentStore is a place for Document's.
type DocumentStore interface {
	// Create data at path.
	// ErrPathExists if path already exists.
	Create(ctx context.Context, path string, b []byte) error

	// Create or set data at path.
	Set(ctx context.Context, path string, b []byte) error

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

	// Documents for Document's.
	Documents(ctx context.Context, parent string, opts *DocumentsOpts) (DocumentIterator, error)

	// Collections are parents of Document's.
	Collections(ctx context.Context, parent string) (CollectionIterator, error)
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

// DocumentsOpts are options for iterating documents.
type DocumentsOpts struct {
	// Prefix to filter on.
	Prefix string
	// Index is offset into number of documents.
	Index int
	// Limit is number of documents (max) to return.
	Limit int
	// PathOnly to only include only path in Document (no data).
	PathOnly bool
}
