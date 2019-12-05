package keys

import (
	"strconv"
	"strings"
)

type marshalStringEntry struct {
	key   string
	value string
}

type marshalIntEntry struct {
	key   string
	value int
}

// MarshalValue to string.
type MarshalValue interface {
	Marshal() string
}

// NewStringEntry ...
func NewStringEntry(key string, value string) MarshalValue {
	return marshalStringEntry{key: key, value: value}
}

// NewIntEntry ...
func NewIntEntry(key string, value int) MarshalValue {
	return marshalIntEntry{key: key, value: value}
}

func (e marshalStringEntry) Marshal() string {
	return `"` + e.key + `":"` + e.value + `"`
}

func (e marshalIntEntry) Marshal() string {
	return `"` + e.key + `":` + strconv.Itoa(e.value)
}

// Marshal map entries.
func Marshal(es []MarshalValue) []byte {
	out := make([]string, 0, len(es))
	for _, e := range es {
		s := e.Marshal()
		out = append(out, s)
	}
	return []byte("{" + strings.Join(out, ",") + "}")
}
