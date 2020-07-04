package docs

import (
	"bytes"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/davecgh/go-spew/spew"
)

// Spew writes Iterator to buffer.
func Spew(iter Iterator) (*bytes.Buffer, error) {
	var b bytes.Buffer
	if err := SpewOut(iter, &b); err != nil {
		return nil, err
	}
	return &b, nil
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
		if !utf8.Valid(doc.Data) {
			if _, err := out.Write([]byte(fmt.Sprintf("%s\n", doc.Path))); err != nil {
				return err
			}
			if _, err := out.Write([]byte(spew.Sdump(doc.Data))); err != nil {
				return err
			}
		} else {
			if _, err := out.Write([]byte(fmt.Sprintf("%s ", doc.Path))); err != nil {
				return err
			}
			if _, err := out.Write([]byte(fmt.Sprintf("%s\n", doc.Data))); err != nil {
				return err
			}
		}
	}
	return nil
}
