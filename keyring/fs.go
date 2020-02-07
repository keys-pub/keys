package keyring

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// NewFS creates a Keyring using the local filesystem. This is an alternate
// Keyring implementation that is platform agnostic.
func NewFS(dir string) (Keyring, error) {
	kr, err := newKeyring(fs{dir: dir}, "")
	if err != nil {
		return nil, err
	}
	return &fkr{kr, dir}, nil
}

type fkr struct {
	*keyring
	dir string
}

func (k *fkr) Reset() error {
	if k.dir == "" {
		return errors.Errorf("empty dir")
	}
	if err := os.RemoveAll(k.dir); err != nil {
		return err
	}
	return k.Lock()
}

type fs struct {
	dir string
}

func (k fs) Get(service string, id string) ([]byte, error) {
	path := filepath.Join(k.dir, id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return ioutil.ReadFile(path)
}

func (k fs) Set(service string, id string, data []byte, typ string) error {
	path := filepath.Join(k.dir, id)
	if err := os.MkdirAll(k.dir, 0700); err != nil {
		return err
	}
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		return errors.Wrapf(err, "failed to write file")
	}
	return nil
}

func (k fs) IDs(service string, prefix string, showHidden bool, showReserved bool) ([]string, error) {
	path := filepath.Join(k.dir, service)
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(files))
	for _, f := range files {
		id := f.Name()
		if !showReserved && strings.HasPrefix(id, reservedPrefix) {
			continue
		}
		if !showHidden && strings.HasPrefix(id, hiddenPrefix) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(id, prefix) {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (k fs) Exists(service string, id string) (bool, error) {
	path := filepath.Join(k.dir, service, id)
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}

func (k fs) Delete(service string, id string) (bool, error) {
	path := filepath.Join(k.dir, service, id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		return true, err
	}
	return true, nil
}
