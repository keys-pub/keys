package keys

import "github.com/pkg/errors"

// Convert tries to convert a Key to another key type.
// This currently only converts a EdX25519 key to a X25519 public key.
func Convert(key Key, to KeyType, public bool) (Key, error) {
	from := key.Type()

	switch from {
	case EdX25519:
		if to == X25519 {
			if public {
				pk, err := NewEdX25519PublicKeyFromID(key.ID())
				if err != nil {
					return nil, err
				}
				return pk.X25519PublicKey(), nil
			}
		}
	}
	return nil, errors.Errorf("failed to convert")
}
