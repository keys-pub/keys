package keys

import (
	"fmt"
	"strings"

	"github.com/keys-pub/keys/bech32"
	"github.com/pkg/errors"
)

// ID a bech32 encoded string.
type ID string

func (i ID) String() string {
	return string(i)
}

// Decode ID into HRP (human readable part) and bytes (data).
func (i ID) Decode() (string, []byte, error) {
	return bech32.Decode(i.String())
}

// NewID creates ID from HRP (human readable part) and bytes.
func NewID(hrp string, b []byte) (ID, error) {
	out, err := bech32.Encode(hrp, b)
	if err != nil {
		return "", err
	}
	return ID(out), nil
}

// MustID returns ID from HRP (human readable part) and bytes, or panics if
// invalid.
func MustID(hrp string, b []byte) ID {
	id, err := NewID(hrp, b)
	if err != nil {
		panic(err)
	}
	return id
}

// ParseID parses a string and validates an ID.
func ParseID(s string) (ID, error) {
	if s == "" {
		return "", errors.Errorf("invalid ID: empty string")
	}
	_, _, err := bech32.Decode(s)
	if err != nil {
		return "", errors.Wrapf(err, "invalid ID")
	}
	return ID(s), nil
}

// IsValidID returns true if string is a valid ID.
func IsValidID(s string) bool {
	_, err := ParseID(s)
	return err == nil
}

// RandID returns random ID
func RandID(hrp string) ID {
	b := Rand32()
	return MustID(hrp, b[:])
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

// WithSeq returns string with a sequence value appended to the ID.
func (i ID) WithSeq(seq int) string {
	if seq == 0 {
		panic("invalid seq")
	}
	return fmt.Sprintf("%s-%015d", i, seq)
}

// IsEdX25519 returns true if ID represents a EdX25519 key.
func (i ID) IsEdX25519() bool {
	hrp, _, err := i.Decode()
	if err != nil {
		return false
	}
	return hrp == edx25519KeyHRP
}

// IsX25519 returns true if ID represents a X25519 key.
func (i ID) IsX25519() bool {
	hrp, _, err := i.Decode()
	if err != nil {
		return false
	}
	return hrp == x25519KeyHRP
}

// PublicKeyType returns public key type that ID represents or empty string if unknown.
func (i ID) PublicKeyType() KeyType {
	hrp, _, err := i.Decode()
	if err != nil {
		return ""
	}
	switch hrp {
	case edx25519KeyHRP:
		return EdX25519Public
	case x25519KeyHRP:
		return X25519Public
	}
	return ""
}

// ID for Keys interface.
func (i ID) ID() ID {
	return i
}

// Type of key.
func (i ID) Type() KeyType {
	hrp, _, err := i.Decode()
	if err != nil {
		return ""
	}
	switch hrp {
	case edx25519KeyHRP:
		return EdX25519Public
	case x25519KeyHRP:
		return X25519Public
	default:
		return ""
	}
}

// Bytes are key data.
func (i ID) Bytes() []byte {
	_, b, err := i.Decode()
	if err != nil {
		return nil
	}
	return b
}

// IDSet is a set of strings.
type IDSet struct {
	keysMap map[ID]bool
	keys    []ID
}

// NewIDSet creates IDSet.
func NewIDSet(ids ...ID) *IDSet {
	return newIDSet(len(ids), ids...)
}

// NewIDSetWithCapacity ..
func NewIDSetWithCapacity(capacity int) *IDSet {
	return newIDSet(capacity)
}

func newIDSet(capacity int, ids ...ID) *IDSet {
	keysMap := make(map[ID]bool, capacity)
	keys := make([]ID, 0, capacity)
	for _, v := range ids {
		keysMap[v] = true
		keys = append(keys, v)
	}
	return &IDSet{
		keysMap: keysMap,
		keys:    keys,
	}
}

// Contains returns true if set contains string.
func (s *IDSet) Contains(id ID) bool {
	return s.keysMap[id]
}

// Add to set.
func (s *IDSet) Add(id ID) {
	if s.Contains(id) {
		return
	}
	s.keysMap[id] = true
	s.keys = append(s.keys, id)
}

// AddAll to set.
func (s *IDSet) AddAll(ids []ID) {
	for _, id := range ids {
		s.Add(id)
	}
}

// Clear set.
func (s *IDSet) Clear() {
	s.keysMap = map[ID]bool{}
	s.keys = []ID{}
}

// IDs returns IDs in set.
func (s *IDSet) IDs() []ID {
	return s.keys
}

// Size for set.
func (s *IDSet) Size() int {
	return len(s.keys)
}
