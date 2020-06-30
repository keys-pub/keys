package keyring

import (
	"sort"
	"strings"

	"github.com/keys-pub/keys/ds"
	"github.com/pkg/errors"
)

// NewMem returns an in memory keyring useful for testing or ephemeral keys.
func NewMem() Keyring {
	return &mem{
		items: map[string][]byte{},
	}
}

type mem struct {
	items map[string][]byte
}

func (k *mem) Name() string {
	return "mem"
}

func (k *mem) Get(id string) ([]byte, error) {
	if id == "" {
		return nil, errors.Errorf("invalid id")
	}
	if b, ok := k.items[id]; ok {
		return b, nil
	}
	return nil, nil
}

func (k *mem) Set(id string, data []byte) error {
	if id == "" {
		return errors.Errorf("invalid id")
	}
	k.items[id] = data
	return nil
}

func (k *mem) Reset() error {
	k.items = map[string][]byte{}
	return nil
}

func (k *mem) Exists(id string) (bool, error) {
	if id == "" {
		return false, errors.Errorf("invalid id")
	}
	_, ok := k.items[id]
	return ok, nil
}

func (k *mem) Delete(id string) (bool, error) {
	if id == "" {
		return false, errors.Errorf("invalid id")
	}
	if _, ok := k.items[id]; ok {
		delete(k.items, id)
		return true, nil
	}
	return false, nil
}

func (k *mem) Documents(opt ...ds.DocumentsOption) ([]*ds.Document, error) {
	opts := ds.NewDocumentsOptions(opt...)
	prefix := opts.Prefix
	docs := make([]*ds.Document, 0, len(k.items))
	for path, b := range k.items {
		if strings.HasPrefix(path, prefix) {
			doc := &ds.Document{Path: path}
			if !opts.NoData {
				doc.Data = b
			}
			docs = append(docs, doc)
		}
	}
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].Path < docs[j].Path
	})
	return docs, nil
}
