// Package dstore describes a document store.
package dstore

import (
	"bytes"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/vmihailenco/msgpack/v4"
)

// Document at a path.
type Document struct {
	// Path of document.
	Path string

	values map[string]interface{}

	// CreatedAt (read only). The time at which the document was created.
	CreatedAt time.Time
	// UpdatedAt (read only). The time at which the document was last changed.
	UpdatedAt time.Time
}

// Set value.
func (d *Document) Set(name string, i interface{}) {
	if d.values == nil {
		d.values = map[string]interface{}{}
	}
	d.values[name] = i
}

// Get value.
func (d *Document) Get(name string) (interface{}, bool) {
	if d.values == nil {
		return nil, false
	}
	i, ok := d.values[name]
	return i, ok
}

// marshal uses msgpack with fallback to json tags.
func marshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := msgpack.NewEncoder(&buf)
	enc.UseJSONTag(true)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// unmarshal uses msgpack with fallback to json tags.
func unmarshal(b []byte, i interface{}) error {
	dec := msgpack.NewDecoder(bytes.NewReader(b))
	dec.UseJSONTag(true)
	if err := dec.Decode(i); err != nil {
		return err
	}
	return nil
}

// From interface to map.
// If error, nil is returned.
// Uses msgpack fallback to json tags to unmarshal into value.
func From(i interface{}) map[string]interface{} {
	b, err := marshal(i)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

// To value.
// Uses msgpack.
func (d *Document) To(i interface{}) error {
	b, err := marshal(d.values)
	if err != nil {
		return err
	}
	return unmarshal(b, i)
}

// SetAll values on document. Overwrites any existing values.
// We do not clone the map.
func (d *Document) SetAll(m map[string]interface{}) {
	d.values = m
}

// Bytes returns document data.
func (d *Document) Bytes(name string) []byte {
	i, ok := d.Get(name)
	if !ok {
		return nil
	}
	switch v := i.(type) {
	case []byte:
		return v
	case string:
		b, err := encoding.Decode(v, encoding.Base64)
		if err != nil {
			return nil
		}
		return b
	default:
		return nil
	}
}

// Int returns document value as int.
func (d *Document) Int(name string) (int, bool) {
	i, ok := d.Get(name)
	if !ok {
		return 0, false
	}
	switch v := i.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	default:
		return 0, false
	}
}

// Int64 returns document value as int64.
func (d *Document) Int64(name string) (int64, bool) {
	i, ok := d.Get(name)
	if !ok {
		return 0, false
	}
	switch v := i.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	default:
		return 0, false
	}
}

// Int returns document data.
func (d *Document) String(name string) (string, bool) {
	i, ok := d.Get(name)
	if !ok {
		return "", false
	}
	switch v := i.(type) {
	case string:
		return v, true
	default:
		return "", false
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

// WithData returns document with data.
func (d *Document) WithData(b []byte) *Document {
	d.Set("data", b)
	return d
}

// With returns document with values.
func (d *Document) With(m map[string]interface{}) *Document {
	d.values = m
	return d
}

// Data returns document data.
func (d *Document) Data() []byte {
	return d.Bytes("data")
}

// Paths from Document's.
func Paths(docs []*Document) []string {
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

// Empty document.
func Empty() map[string]interface{} {
	return map[string]interface{}{}
}
