// Package json provides a simpler JSON marshaller for strings and ints only.
package json

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"

	"github.com/keys-pub/keys/encoding"

	"github.com/pkg/errors"
)

type stringEntry struct {
	key   string
	value string
}

type intEntry struct {
	key   string
	value int
}

// String ...
func String(key string, value string) encoding.TextMarshaler {
	return stringEntry{key: key, value: value}
}

// Int ...
func Int(key string, value int) encoding.TextMarshaler {
	return intEntry{key: key, value: value}
}

var isAlphaNumericDot = regexp.MustCompile(`^[a-zA-Z0-9.]+$`).MatchString
var needsEscape = regexp.MustCompile(`^[\"]+$`).MatchString

func (e stringEntry) MarshalText() ([]byte, error) {
	if !isAlphaNumericDot(e.key) {
		return nil, errors.Errorf("invalid character in key")
	}
	if needsEscape(e.value) {
		return nil, errors.Errorf("invalid character in value")
	}
	if !encoding.IsASCII([]byte(e.value)) {
		return nil, errors.Errorf("invalid character in value")
	}
	return []byte(`"` + e.key + `":"` + e.value + `"`), nil
}

func (e intEntry) MarshalText() ([]byte, error) {
	if !isAlphaNumericDot(e.key) {
		return nil, errors.Errorf("invalid character in key")
	}

	b := []byte{}
	b = append(b, '"')
	b = append(b, []byte(e.key)...)
	b = append(b, '"', ':')
	b = append(b, []byte(strconv.Itoa(e.value))...)

	return b, nil
}

// Marshal values.
func Marshal(vals ...encoding.TextMarshaler) ([]byte, error) {
	out := make([][]byte, 0, len(vals))
	for _, val := range vals {
		b, err := val.MarshalText()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}

	b := []byte{}
	b = append(b, '{')
	b = append(b, bytes.Join(out, []byte{','})...)
	b = append(b, '}')

	return b, nil
}

// Unmarshal bytes.
func Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
