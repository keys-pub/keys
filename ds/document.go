// Package ds describes documents and document stores.
package ds

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/davecgh/go-spew/spew"
)

// Document is a data at a path with metadata.
type Document struct {
	// Path of document.
	Path string `json:"path" msgpack:"p"`
	// Data ...
	Data []byte `json:"data" msgpack:"dat"`

	// CreatedAt (read only). The time at which the document was created.
	CreatedAt time.Time `json:"cts" msgpack:"cts"`
	// UpdatedAt (read only). The time at which the document was last changed.
	UpdatedAt time.Time `json:"uts" msgpack:"uts"`
}

func (d Document) String() string {
	return fmt.Sprintf("%s %s", d.Path, spew.Sdump(d.Data))
}

// Name for document (last path component).
func (d Document) Name() string {
	return LastPathComponent(d.Path)
}

// NewDocument creates a datastore document.
func NewDocument(path string, data []byte) *Document {
	return &Document{
		Path: Path(path),
		Data: data,
	}
}

// Contains returns true if path or value contains the string.
func (d *Document) Contains(contains string) bool {
	if contains == "" {
		return true
	}
	if d.Path != "" && strings.Contains(d.Path, contains) {
		return true
	}
	if utf8.Valid(d.Data) {
		return strings.Contains(string(d.Data), contains)
	}
	return false
}

// Pretty returns "prettified" output, if data is a format that supports it.
func (d *Document) Pretty() []byte {
	if len(d.Data) > 1 && string(d.Data[0]) == "{" {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, d.Data, "", "  "); err != nil {
			return pretty.Bytes()
		}
	}
	return nil
}

// DocumentPaths from Document's.
func DocumentPaths(docs []*Document) []string {
	paths := make([]string, 0, len(docs))
	for _, doc := range docs {
		paths = append(paths, doc.Path)
	}
	return paths
}

// Collection is a location for Document's.
type Collection struct {
	// Path for collection.
	Path string
}
