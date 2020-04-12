package json

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

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

// Value to string.
type Value interface {
	Marshal() (string, error)
}

// NewString ...
func NewString(key string, value string) Value {
	return stringEntry{key: key, value: value}
}

// NewInt ...
func NewInt(key string, value int) Value {
	return intEntry{key: key, value: value}
}

var isAlphaNumericDot = regexp.MustCompile(`^[a-zA-Z0-9.]+$`).MatchString
var needsEscape = regexp.MustCompile(`^[\"]+$`).MatchString

func (e stringEntry) Marshal() (string, error) {
	if !isAlphaNumericDot(e.key) {
		return "", errors.Errorf("invalid character in key")
	}
	if needsEscape(e.value) {
		return "", errors.Errorf("invalid character in value")
	}
	if !encoding.IsASCII([]byte(e.value)) {
		return "", errors.Errorf("invalid character in value")
	}
	return `"` + e.key + `":"` + e.value + `"`, nil
}

func (e intEntry) Marshal() (string, error) {
	if !isAlphaNumericDot(e.key) {
		return "", errors.Errorf("invalid character in key")
	}
	return `"` + e.key + `":` + strconv.Itoa(e.value), nil
}

// Marshal values.
func Marshal(es []Value) ([]byte, error) {
	out := make([]string, 0, len(es))
	for _, e := range es {
		s, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return []byte("{" + strings.Join(out, ",") + "}"), nil
}

func Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
