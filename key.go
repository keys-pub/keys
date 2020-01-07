package keys

// Key with identifier, bytes and type string.
type Key interface {
	// ID for the key.
	ID() ID

	// Bytes for key.
	Bytes() []byte

	// Type of key.
	Type() string
}
