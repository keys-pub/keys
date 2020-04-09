package keys

import "time"

// Key with identifier, bytes and type string.
type Key interface {
	// ID for the key.
	ID() ID

	// Type of key.
	Type() KeyType

	// Bytes are key data.
	Bytes() []byte

	// Metadata
	Metadata() *Metadata
}

// KeyType ...
type KeyType string

var _ Key = &EdX25519Key{}
var _ Key = &EdX25519PublicKey{}
var _ Key = &X25519Key{}
var _ Key = &X25519PublicKey{}

// Metadata for key.
type Metadata struct {
	Notes     string
	CreatedAt time.Time
	// UpdatedAt time.Time
}
