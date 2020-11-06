// Package docs provides a document store.
package docs

import (
	"time"
)

// Document is data at a path.
type Document struct {
	// Path of document.
	Path string

	values map[string]interface{}

	// CreatedAt (read only). The time at which the document was created.
	CreatedAt time.Time
	// UpdatedAt (read only). The time at which the document was last changed.
	UpdatedAt time.Time
}

// SetValue sets document value.
func (d *Document) SetValue(name string, i interface{}) {
	d.values[name] = i
}

// Bytes returns document data.
func (d *Document) Bytes(name string) []byte {
	i, ok := d.values[name]
	if !ok {
		return nil
	}
	switch v := i.(type) {
	case []byte:
		return v
	default:
		return nil
	}
}

// NewDocument creates a document with data.
func NewDocument(path string) *Document {
	return &Document{
		Path:      Path(path),
		values:    map[string]interface{}{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// WithData adds data to document.
func (d *Document) WithData(b []byte) *Document {
	d.SetValue("data", b)
	return d
}

// Data returns document data.
func (d *Document) Data() []byte {
	return d.Bytes("data")
}

// // Contains returns true if path or value contains the string.
// func (d *Document) Contains(contains string) bool {
// 	if contains == "" {
// 		return true
// 	}
// 	if d.Path != "" && strings.Contains(d.Path, contains) {
// 		return true
// 	}
// 	if utf8.Valid(d.Data) {
// 		return strings.Contains(string(d.Data), contains)
// 	}
// 	return false
// }

// // Pretty returns "prettified" output, if data is a format that supports it.
// func (d *Document) Pretty() []byte {
// 	if len(d.Data) > 1 && string(d.Data[0]) == "{" {
// 		var pretty bytes.Buffer
// 		if err := json.Indent(&pretty, d.Data, "", "  "); err != nil {
// 			return pretty.Bytes()
// 		}
// 	}
// 	return nil
// }

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
