package backup

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"time"
)

type tgz struct {
	file *os.File
	gz   *gzip.Writer
	tw   *tar.Writer
}

func newTgz(out string) (*tgz, error) {
	file, err := os.Create(out)
	if err != nil {
		return nil, err
	}

	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	return &tgz{
		file: file,
		gz:   gz,
		tw:   tw,
	}, nil
}

func (t *tgz) Close() {
	t.tw.Close()
	t.gz.Close()
	t.file.Close()
}

func (t *tgz) Add(name string, reader io.Reader, size int64, modTime time.Time) error {
	header := new(tar.Header)
	header.Name = name
	header.Size = size
	header.Mode = 0600
	header.ModTime = modTime
	if err := t.tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := io.Copy(t.tw, reader); err != nil {
		return err
	}
	return nil
}
