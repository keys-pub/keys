package keys

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
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
	GetAll(ctx context.Context, paths []string) ([]*Document, error)

	// Exists, if exists at path.
	Exists(ctx context.Context, path string) (bool, error)

	// Delete at path.
	Delete(ctx context.Context, path string) (bool, error)

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

// CryptoStore is a DocumentStore with a CryptoProvider.
type CryptoStore struct {
	DocumentStore
	crypto CryptoProvider
	nowFn  func() time.Time
}

// NewCryptoStore creates a CryptoStore.
func NewCryptoStore(ds DocumentStore, crypto CryptoProvider) *CryptoStore {
	return &CryptoStore{
		ds,
		crypto,
		time.Now,
	}
}

// Now returns current time.
func (d *CryptoStore) Now() time.Time {
	return d.nowFn()
}

// SetTimeNow to use a custom time.Now.
func (d *CryptoStore) SetTimeNow(nowFn func() time.Time) {
	d.nowFn = nowFn
}

// Sign ...
func (d *CryptoStore) Sign(ctx context.Context, path string, b []byte, key *SignKey) ([]byte, error) {
	out, err := d.crypto.Sign(b, key)
	if err != nil {
		return nil, err
	}
	if err := d.Create(ctx, path, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Verified data with signer ID and the originating DocumentStore
// Entry.
type Verified struct {
	Data     []byte
	Document *Document
	Signer   ID
}

// Verify ...
func (d *CryptoStore) Verify(ctx context.Context, path string) (*Verified, error) {
	if path == "" {
		return nil, errors.Errorf("no path specified")
	}
	doc, err := d.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	data, signer, err := d.crypto.Verify(doc.Data)
	if err != nil {
		return nil, err
	}
	return &Verified{
		Data:     data,
		Signer:   SignPublicKeyID(signer),
		Document: doc,
	}, nil
}

// Seal ...
func (d *CryptoStore) Seal(ctx context.Context, path string, b []byte, sender Key, recipients ...PublicKey) ([]byte, error) {
	out, err := d.crypto.Seal(b, sender, recipients...)
	if err != nil {
		return nil, err
	}
	if err := d.Create(ctx, path, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Opened contains decrypted data with the PublicKey used to sign, and the
// originating DocumentStore Entry.
type Opened struct {
	Data     []byte
	Signer   ID
	Document *Document
}

// Open ...
func (d *CryptoStore) Open(ctx context.Context, path string) (*Opened, error) {
	if path == "" {
		return nil, errors.Errorf("no path specified")
	}
	doc, err := d.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	data, signer, err := d.crypto.Open(doc.Data)
	if err != nil {
		return nil, err
	}
	return &Opened{
		Data:     data,
		Signer:   signer,
		Document: doc,
	}, nil
}
