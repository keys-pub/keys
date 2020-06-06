package keyring

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// FS Store option.
func FS(dir string, versioned bool) Option {
	return func(o *Options) error {
		st, err := NewFS(dir, versioned)
		if err != nil {
			return err
		}
		o.st = st
		return nil
	}
}

// NewFS returns keyring.Store backed by the filesystem.
//
// If versioned is true, it returns a filesystem that is create (append) only,
// which means any update or delete creates a new file (version).
// TODO: Link to version filesystem spec.
//
// A versioned filesystem is also necessary if you want to use backup/sync to
// a remote bucket/git etc.
func NewFS(dir string, versioned bool) (Store, error) {
	if versioned {
		return newFSV(dir)
	}
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
		return nil, errors.Errorf("failed to get keyring item: no id specified")
	}
	if id == "." || id == ".." || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return nil, errors.Errorf("failed to get keyring item: invalid id %q", id)
	}

	path := filepath.Join(k.dir, id)
	exists, err := pathExists(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return ioutil.ReadFile(path) // #nosec
}

func (k fs) Set(id string, data []byte) error {
	if id == "" {
		return errors.Errorf("no id specified")
	}
	if err := os.MkdirAll(k.dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(k.dir, id)
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		return errors.Wrapf(err, "failed to write file")
	}
	return nil
}

func (k fs) IDs(opts ...IDsOption) ([]string, error) {
	options := NewIDsOptions(opts...)
	prefix, showHidden, showReserved := options.Prefix, options.Hidden, options.Reserved

	exists, err := pathExists(k.dir)
	if err != nil {
		return nil, err
	}
	if !exists {
		return []string{}, nil
	}

	files, err := ioutil.ReadDir(k.dir)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(files))
	for _, f := range files {
		id := f.Name()
		if !showReserved && strings.HasPrefix(id, ReservedPrefix) {
			continue
		}
		if !showHidden && strings.HasPrefix(id, HiddenPrefix) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(id, prefix) {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (k fs) Reset() error {
	if err := os.RemoveAll(k.dir); err != nil {
		return err
	}
	return nil
}

func (k fs) Exists(id string) (bool, error) {
	path := filepath.Join(k.dir, id)
	return pathExists(path)
}

func (k fs) Delete(id string) (bool, error) {
	path := filepath.Join(k.dir, id)

	exists, err := pathExists(path)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		return true, err
	}
	return true, nil
}

func pathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}
