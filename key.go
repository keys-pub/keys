package keys

// Key with identifier, bytes and a type.
type Key interface {
	// ID for the key.
	ID() ID

	// Type of key.
	Type() KeyType

	// Private key data.
	Private() []byte

	// Public key data.
	Public() []byte
}

// KeyType ...
type KeyType string

var _ Key = &EdX25519Key{}
var _ Key = &EdX25519PublicKey{}
var _ Key = &X25519Key{}
var _ Key = &X25519PublicKey{}
var _ Key = ID("")

var _ Key = &RSAKey{}
var _ Key = &RSAPublicKey{}
