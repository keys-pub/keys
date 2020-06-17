package keyring

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/keys-pub/keys/ds"
	"github.com/pkg/errors"
)

// NewFS returns keyring.Store backed by the filesystem.
func NewFS(dir string) (Store, error) {
	return newFS(dir)
}

func newFS(dir string) (Store, error) {
	if dir == "" || dir == "/" {
		return nil, errors.Errorf("invalid directory")
	}
	return fs{dir: dir}, nil
}

type fs struct {
	dir string
}

func (k fs) Name() string {
	return "fs"
}

func (k fs) Get(id string) ([]byte, error) {
	if id == "" {
		return nil, errors.Errorf("invalid id")
	}
	if id == "." || id == ".." {
		return nil, errors.Errorf("invalid id %s", id)
	}

	fpath := filepath.Join(k.dir, id)
	exists, err := pathExists(fpath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return ioutil.ReadFile(fpath) // #nosec
}

func (k fs) Set(id string, data []byte) error {
	if id == "" {
		return errors.Errorf("invalid path")
	}
	if err := os.MkdirAll(k.dir, 0700); err != nil {
		return err
	}
	fpath := filepath.Join(k.dir, id)

	// Ensure directories if
	fdir, _ := filepath.Split(fpath)
	if err := os.MkdirAll(fdir, 0700); err != nil {
		return err
	}

	if err := ioutil.WriteFile(fpath, data, 0600); err != nil {
		return errors.Wrapf(err, "failed to write file")
	}
	return nil
}

func (k fs) Reset() error {
	if err := os.RemoveAll(k.dir); err != nil {
		return err
	}
	return nil
}

func (k fs) Exists(id string) (bool, error) {
	fpath := filepath.Join(k.dir, id)
	return pathExists(fpath)
}

func (k fs) Delete(id string) (bool, error) {
	fpath := filepath.Join(k.dir, id)

	exists, err := pathExists(fpath)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if err := os.Remove(fpath); err != nil {
		return true, err
	}
	return true, nil
}

func pathExists(id string) (bool, error) {
	if _, err := os.Stat(id); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}

func (k fs) Documents(opt ...ds.DocumentsOption) (ds.DocumentIterator, error) {
	opts := ds.NewDocumentsOptions(opt...)
	prefix := opts.Prefix

	files, err := ioutil.ReadDir(k.dir)
	if err != nil {
		return nil, err
	}

	docs := make([]*ds.Document, 0, len(files))
	for _, f := range files {
		name := f.Name()
		if strings.HasPrefix(name, prefix) {
			// TODO: Iterator
			doc := &ds.Document{Path: name}
			if !opts.NoData {
				b, err := ioutil.ReadFile(filepath.Join(k.dir, name))
				if err != nil {
					return nil, err
				}
				doc.Data = b
			}
			docs = append(docs, doc)
		}
	}
	// sort.Slice(docs, func(i, j int) bool {
	// 	return docs[i].Path < docs[j].Path
	// })

	return ds.NewDocumentIterator(docs...), nil
}
