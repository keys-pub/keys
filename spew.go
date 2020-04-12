package keys

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"text/tabwriter"
	"unicode/utf8"
)

// SpewFormat is format for Spew.
type SpewFormat string

const (
	// SpewFormatDefault ...
	SpewFormatDefault SpewFormat = ""
	// SpewFormatTable is in a grid, each entry separated by newlines.
	SpewFormatTable SpewFormat = "table"
	// SpewFormatFlat are fields separated by newlines and entries separated by empty lines.
	SpewFormatFlat SpewFormat = "flat"
)

// SpewOpts are options for Spew.
type SpewOpts struct {
	Format SpewFormat
}

// Spew writes DocumentIterator to buffer.
func Spew(iter DocumentIterator, opts *SpewOpts) (*bytes.Buffer, error) {
	var b bytes.Buffer
	if err := SpewOut(iter, opts, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// SpewOut writes DocumentIterator to io.Writer.
// You need to specify a path or prefix, since listing root is not supported.
func SpewOut(iter DocumentIterator, opts *SpewOpts, out io.Writer) error {
	if opts == nil {
		opts = &SpewOpts{}
	}
	ofmt := opts.Format
	if ofmt == "" {
		ofmt = SpewFormatTable
	}

	// out.Write([]byte("\n"))
	switch ofmt {
	case SpewFormatTable:
		w := new(tabwriter.Writer)
		w.Init(out, 0, 8, 1, ' ', 0)
		for {
			doc, err := iter.Next()
			if err != nil {
				return err
			}
			if doc == nil {
				break
			}
			key := doc.Path
			value := ""
			if !utf8.Valid(doc.Data) {
				value = hex.EncodeToString(doc.Data)
			} else {
				value = string(doc.Data)
			}
			fmt.Fprintf(w, "%s\t%s\n", key, value)
		}
		if err := w.Flush(); err != nil {
			return err
		}
	case SpewFormatFlat:
		for {
			doc, err := iter.Next()
			if err != nil {
				return err
			}
			if doc == nil {
				break
			}
			key := doc.Path
			value := ""
			if !utf8.Valid(doc.Data) {
				value = hex.EncodeToString(doc.Data)
			} else {
				value = string(doc.Data)
			}
			if _, err := out.Write([]byte(fmt.Sprintf("%s\n", key))); err != nil {
				return err
			}
			if _, err := out.Write([]byte(fmt.Sprintf("%s\n", value))); err != nil {
				return err
			}
			if _, err := out.Write([]byte("\n")); err != nil {
				return err
			}
		}
	}
	return nil
}
