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

// Backup Store into {path}.tgz.
func Backup(path string, st Store, now time.Time) error {
	tmpPath := path + ".tmp"
	defer func() { _ = os.Remove(tmpPath) }()

	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	if err := backup(file, st, now); err != nil {
		_ = file.Close()
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	return nil
}

func backup(file *os.File, st Store, now time.Time) error {
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)

	ids, err := st.IDs(Reserved())
	if err != nil {
		_ = tw.Close()
		_ = gz.Close()
		return err
	}
	for _, id := range ids {
		b, err := st.Get(id)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return err
		}

		header := new(tar.Header)
		header.Name = id
		header.Size = int64(len(b))
		header.Mode = 0600
		header.ModTime = now
		if err := tw.WriteHeader(header); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return err
		}
		if _, err := io.Copy(tw, bytes.NewReader(b)); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	return nil
}

// Restore from path.tgz into Store.
func Restore(path string, st Store) error {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return errors.Wrapf(err, "failed to open backup")
	}

	if err := restore(file, st); err != nil {
		_ = file.Close()
		return err
	}

	return file.Close()

}

func restore(file *os.File, st Store) error {
	gz, err := gzip.NewReader(file)
	if err != nil {
		return errors.Wrapf(err, "failed to open gzip")
	}

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrapf(err, "failed to read next tar")
		}

		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			b, err := ioutil.ReadAll(tr)
			if err != nil {
				return errors.Wrapf(err, "failed to read tar")
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
