package keyring

import "github.com/keys-pub/keys/ds"

// Store is the interface used to store data.
type Store interface {
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

// Paths from Store.
func Paths(st Store, prefix string) ([]string, error) {
	iter, err := st.Documents(ds.Prefix(prefix), ds.NoData())
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

// Documents from Store.
func Documents(st Store, prefix string) ([]*ds.Document, error) {
	iter, err := st.Documents(ds.Prefix(prefix))
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

func reset(st Store) error {
	paths, err := Paths(st, "")
	if err != nil {
		return err
	}
	for _, p := range paths {
		if _, err := st.Delete(p); err != nil {
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
