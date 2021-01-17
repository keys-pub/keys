package dstore

import (
	"bytes"
	"io"

	"github.com/davecgh/go-spew/spew"
)

// Spew writes Iterator to buffer.
func Spew(iter Iterator) (string, error) {
	var b bytes.Buffer
	if err := SpewOut(iter, &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

// SpewOut writes Iterator to io.Writer.
func SpewOut(iter Iterator, out io.Writer) error {
	for {
		doc, err := iter.Next()
		if err != nil {
			return err
		}
		if doc == nil {
			break
		}
		if _, err := out.Write([]byte(spew.Sdump(doc))); err != nil {
			return err
		}
	}
	return nil
}
