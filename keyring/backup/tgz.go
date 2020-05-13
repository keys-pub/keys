package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

type tgz struct {
	path  string
	nowFn func() time.Time
}

// NewTGZStore creates a Store for a tar/gz file (tgz).
func NewTGZStore(path string, nowFn func() time.Time) Store {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &tgz{path: path, nowFn: nowFn}
}

func (t *tgz) SaveItems(items []*keyring.Item, key keyring.SecretKey) error {
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
	for _, item := range items {
		b, err := item.Marshal(key)
		if err != nil {
			return err
		}

		header := new(tar.Header)
		header.Name = keys.Rand3262()
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

func (t *tgz) ListItems(key keyring.SecretKey) ([]*keyring.Item, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	tr := tar.NewReader(gz)
	items := []*keyring.Item{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			b, err := ioutil.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			item, err := keyring.NewItemFromBytes(b, key)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		default:
			return nil, errors.Errorf("invalid tar flag")
		}
	}

	return items, nil
}
