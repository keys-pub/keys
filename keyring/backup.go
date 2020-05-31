package keyring

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/pkg/errors"
)

// Backup Store into TGZ.
func Backup(path string, st Store, now time.Time) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz := gzip.NewWriter(file)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	ids, err := st.IDs(Hidden(), Reserved())
	if err != nil {
		return err
	}
	for _, id := range ids {
		b, err := st.Get(id)
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

// Restore from path.tgz into Store.
func Restore(path string, st Store) error {
	f, err := os.Open(path)
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
			if err := st.Set(id, b); err != nil {
				return err
			}

		default:
			return errors.Errorf("invalid tar flag")
		}
	}

	return nil
}
