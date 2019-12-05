package keys

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// ID is a 32 byte Base58 (19/26-rate) encoded string of 44 characters
type ID string

func encodeID(b []byte) (string, error) {
	if len(b) != 32 {
		return "", errors.Errorf("failed to encode ID: expecting 32 bytes (got %d)", len(b))
	}
	s := MustEncode(b[:], Base58)
	if len(s) < 44 {
		// s = s + strings.Repeat("1", 44-len(s))
		return "", errors.Errorf("failed to encode ID: expecting 44 characters (got %d)", len(s))
	}
	return s, nil
}

func decodeID(s string) ([]byte, error) {
	if len(s) != 44 {
		return nil, errors.Errorf("failed to decode ID: expecting 44 characters (got %d)", len(s))
	}
	b, err := Decode(s, Base58)
	if err != nil {
		return nil, err
	}
	if len(b) > 32 {
		return nil, errors.Errorf("failed to decode ID: too many bytes")
	}
	return b, nil
}

func (i ID) String() string {
	return string(i)
}

// WithSeq returns ID with a sequence value appended
func (i ID) WithSeq(seq int) string {
	if seq == 0 {
		panic("invalid seq")
	}
	return fmt.Sprintf("%s-%015d", i, seq)
}

// Bytes ...
func (i ID) Bytes() []byte {
	b, err := decodeID(string(i))
	if err != nil {
		panic(err)
	}
	return b
}

// Index is first 4 bytes as uint32
func (i ID) Index() uint32 {
	return binary.BigEndian.Uint32(i.Bytes()[0:4])
}

// NewID creates ID from bytes
func NewID(b []byte) (ID, error) {
	s, err := encodeID(b)
	if err != nil {
		return "", err
	}
	return ID(s), nil
}

// MustID returns ID from bytes, or panics if invalid.
func MustID(b []byte) ID {
	s, err := encodeID(b)
	if err != nil {
		panic(err)
	}
	return ID(s)
}

// ParseID parses a string and validates an ID.
func ParseID(s string) (ID, error) {
	if s == "" {
		return "", errors.Errorf("invalid ID: empty string")
	}
	b, err := decodeID(s)
	if err != nil {
		return "", err
	}
	out, err := encodeID(b)
	if err != nil {
		return "", err
	}
	return ID(out), nil
}

// IsValidID returns true if string is a valid ID
func IsValidID(s string) bool {
	_, err := ParseID(s)
	return err == nil
}

// RandID returns random ID
func RandID() ID {
	b := randBytes(32)
	return MustID(b[:])
}

// IDsToStrings returns []strings for []ID.
func IDsToStrings(ids []ID) []string {
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, id.String())
	}
	return strs
}

// IDsToString returns string for joined Ikeys.
func IDsToString(ids []ID, delim string) string {
	return strings.Join(IDsToStrings(ids), delim)
}

// ParseIDs returns IDs from strings.
func ParseIDs(strs []string) ([]ID, error) {
	ids := make([]ID, 0, len(strs))
	for _, s := range strs {
		id, err := ParseID(s)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
