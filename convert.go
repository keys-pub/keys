package keys

import "github.com/pkg/errors"

// Convert tries to convert a Key to another key type.
// This currently only converts a EdX25519Public key to a X25519Public key.
func Convert(key Key, to KeyType) (Key, error) {
	from := key.Type()
	if from == to {
		return nil, errors.Errorf("same key types")
	}

	switch from {
	case EdX25519Public:
		if to == X25519Public {
			pk, err := NewEdX25519PublicKeyFromID(key.ID())
			if err != nil {
				return nil, err
			}
			return pk.X25519PublicKey(), nil
		}
	}
	return nil, errors.Errorf("failed to convert %s to %s", from, to)
}
