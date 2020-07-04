package docs

import (
	"bytes"
	"fmt"
	"io"

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
// You need to specify a path or prefix, since listing root is not supported.
func SpewOut(iter Iterator, out io.Writer) error {
	for {
		doc, err := iter.Next()
		if err != nil {
			return err
		}
		if doc == nil {
			break
		}
		key := doc.Path
		value := spew.Sdump(doc.Data)
		if _, err := out.Write([]byte(fmt.Sprintf("%s\n", key))); err != nil {
			return err
		}
		if _, err := out.Write([]byte(fmt.Sprintf("%s", value))); err != nil {
			return err
		}
		if _, err := out.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}
