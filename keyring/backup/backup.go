package backup

import (
	"crypto/subtle"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Export is the backup format.
type Export struct {
	Items []*keyring.Item `msgpack:"items"`
}

// ExportOpts are options for Export.
type ExportOpts struct {
	Now func() time.Time
}

const timeFormat = "20060102T150405"

// ExportToDirectory saves backup to a directory, encrypted with password.
func ExportToDirectory(kr *keyring.Keyring, dir string, password string, opts *ExportOpts) (string, error) {
	if opts == nil {
		opts = &ExportOpts{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	now := opts.Now().UTC()

	exp, err := newExport(kr, now)
	if err != nil {
		return "", err
	}
	out, err := exp.Marshal(password)
	if err != nil {
		return "", err
	}

	id := keys.Rand3262()
	fileName := fmt.Sprintf("%s-%s.kpb", now.Format(timeFormat), id)

	path := filepath.Join(dir, fileName)
	tmpPath := path + ".tmp"

	if _, err := os.Stat(path); err == nil {
		return "", errors.Errorf("path already exists: %s", path)
	}
	if _, err := os.Stat(tmpPath); err == nil {
		return "", errors.Errorf("path already exists: %s", tmpPath)
	}

	defer func() { _ = os.Remove(tmpPath) }()
	if err := ioutil.WriteFile(tmpPath, out, 0600); err != nil {
		return "", err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return "", err
	}

	return path, nil
}

func newExport(kr *keyring.Keyring, ts time.Time) (*Export, error) {
	items, err := kr.List(nil)
	if err != nil {
		return nil, err
	}
	return &Export{
		Items: items,
	}, nil
}

// Marshal export to bytes.
func (e *Export) Marshal(password string) ([]byte, error) {
	b, err := msgpack.Marshal(e)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal kerying item")
	}

	encrypted := keys.EncryptWithPassword(b, password)

	return encrypted, nil
}

// NewExportFromBytes ...
func NewExportFromBytes(b []byte, password string) (*Export, error) {
	decrypted, err := keys.DecryptWithPassword(b, password)
	if err != nil {
		return nil, err
	}

	var export Export
	if err := msgpack.Unmarshal(decrypted, &export); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal export")
	}

	return &export, nil
}

// ImportFromFile imports backup from file into the Keyring.
// TODO: Dry run.
// TODO: Continue on error.
func ImportFromFile(kr *keyring.Keyring, path string, password string) error {
	b, err := ioutil.ReadFile(path) // #nosec
	if err != nil {
		return err
	}

	export, err := NewExportFromBytes(b, password)
	if err != nil {
		return err
	}

	for _, item := range export.Items {
		existing, err := kr.Get(item.ID)
		if err != nil {
			return err
		}
		if existing != nil {
			if subtle.ConstantTimeCompare(item.Data, existing.Data) != 1 {
				return errors.Errorf("item already exists with different data")
			}
			if item.Type != existing.Type {
				return errors.Errorf("item already exists with different type")
			}
			// It's ok if creation date is different.
			// if item.CreatedAt != existing.CreatedAt {
			// 	return errors.Errorf("item already exists with different creation date")
			// }
		} else {
			if err := kr.Create(item); err != nil {
				return err
			}
		}
	}

	return nil
}
