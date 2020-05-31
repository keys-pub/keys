package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

type tgz struct {
	path  string
	nowFn func() time.Time
}

// NewTGZ implements backup for a tar/gz file (tgz).
func NewTGZ(path string, nowFn func() time.Time) Backup {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &tgz{path: path, nowFn: nowFn}
}

func (t *tgz) Backup(service string, st keyring.Store) error {
	file, err := os.Create(t.path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz := gzip.NewWriter(file)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	now := t.nowFn()

	ids, err := st.IDs(service, keyring.Hidden(), keyring.Reserved())
	if err != nil {
		return err
	}
	for _, id := range ids {
		b, err := st.Get(service, id)
		if err != nil {
			return err
		}

		header := new(tar.Header)
		header.Name = id
		header.Size = int64(len(b))
		header.Mode = 0600
		header.ModTime = now
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := io.Copy(tw, bytes.NewReader(b)); err != nil {
			return err
		}
	}
	return nil
}

func (t *tgz) Restore(service string, st keyring.Store) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			b, err := ioutil.ReadAll(tr)
			if err != nil {
				return err
			}

			id := header.Name
			if err := st.Set(service, id, b); err != nil {
				return err
			}

		default:
			return errors.Errorf("invalid tar flag")
		}
	}

	return nil
}
