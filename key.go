package keys

// Key with identifier, bytes and type string.
type Key interface {
	// ID for the key.
	ID() ID

	// Type of key.
	Type() KeyType

	// Bytes are key data.
	Bytes() []byte
}

// KeyType ...
type KeyType string

// SignKey is a EdX25519Key.
type SignKey = EdX25519Key

// SignPublicKey is a EdX25519PublicKey.
type SignPublicKey = EdX25519PublicKey

// BoxKey is a X25519Key.
type BoxKey = X25519Key

// BoxPublicKey is a X25519PublicKey.
type BoxPublicKey = X25519PublicKey

var _ Key = &EdX25519Key{}
var _ Key = &EdX25519PublicKey{}
var _ Key = &X25519Key{}
var _ Key = &X25519PublicKey{}
