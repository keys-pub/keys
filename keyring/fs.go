package keyring

import (
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// NewFS creates a Keyring using the local filesystem. This is an alternate
// Keyring implementation that is platform agnostic.
func NewFS(service string, dir string) (*Keyring, error) {
	if service == "" {
		return nil, errors.Errorf("no service specified")
	}
	fs, err := FS(dir)
	if err != nil {
		return nil, err
	}
	kr, err := New(service, fs)
	if err != nil {
		return nil, err
	}
	return kr, nil
}

// FS returns keyring.Store backed by the filesystem.
func FS(dir string) (Store, error) {
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

func (k fs) Get(service string, id string) ([]byte, error) {
	if id == "" {
		return nil, errors.Errorf("failed to get keyring item: no id specified")
	}
	if id == "." || id == ".." || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return nil, errors.Errorf("failed to get keyring item: invalid id %q", id)
	}

	path := filepath.Join(k.dir, service, id)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return ioutil.ReadFile(path) // #nosec
}

func (k fs) Set(service string, id string, data []byte) error {
	if id == "" {
		return errors.Errorf("no id specified")
	}
	dir := filepath.Join(k.dir, service)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, id)
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		return errors.Wrapf(err, "failed to write file")
	}
	return nil
}

func (k fs) IDs(service string, opts ...IDsOption) ([]string, error) {
	options := NewIDsOptions(opts...)
	prefix, showHidden, showReserved := options.Prefix, options.Hidden, options.Reserved

	path := filepath.Join(k.dir, service)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []string{}, nil
	}

	files, err := ioutil.ReadDir(path)
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

func (k fs) Reset(service string) error {
	path := filepath.Join(k.dir, service)
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return nil
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

func defaultLinuxFSDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, ".keyring"), nil
}
