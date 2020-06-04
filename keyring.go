package keys

import (
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// x25519KeyForItem returns a X25519Key for a keyring Item.
// If item is a EdX25519Key it's converted to a X25519Key.
func x25519KeyForItem(item *keyring.Item) (*X25519Key, error) {
	switch item.Type {
	case string(X25519):
		bk := NewX25519KeyFromPrivateKey(Bytes32(item.Data))
		return bk, nil
	case string(EdX25519):
		sk, err := edx25519KeyForItem(item)
		if err != nil {
			return nil, err
		}
		return sk.X25519Key(), nil
	default:
		return nil, errors.Errorf("item type %s != %s", item.Type, string(X25519))
	}
}

// edx25519KeyForItem returns EdX25519Key for keyring Item.
func edx25519KeyForItem(item *keyring.Item) (*EdX25519Key, error) {
	if item.Type != string(EdX25519) {
		return nil, errors.Errorf("item type %s != %s", item.Type, string(EdX25519))
	}
	b := item.Data
	if len(b) != 64 {
		return nil, errors.Errorf("invalid number of bytes for ed25519 private key")
	}
	key := NewEdX25519KeyFromPrivateKey(Bytes64(b))
	return key, nil
}

// edx25519PublicKeyForItem returns EdX25519PublicKey for keyring Item.
func edx25519PublicKeyForItem(item *keyring.Item) (*EdX25519PublicKey, error) {
	switch item.Type {
	case string(EdX25519Public):
		b := item.Data
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for ed25519 public key")
		}
		key := NewEdX25519PublicKey(Bytes32(b))
		return key, nil
	case string(EdX25519):
		sk, err := edx25519KeyForItem(item)
		if err != nil {
			return nil, err
		}
		return sk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for edx25519 public key: %s", item.Type)
	}
}

// x25519PublicKeyForItem returns X25519PublicKey for keyring Item.
func x25519PublicKeyForItem(item *keyring.Item) (*X25519PublicKey, error) {
	switch item.Type {
	case string(X25519Public):
		b := item.Data
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for x25519 public key")
		}
		key := NewX25519PublicKey(Bytes32(b))
		return key, nil
	case string(X25519):
		bk, err := x25519KeyForItem(item)
		if err != nil {
			return nil, err
		}
		return bk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for x25519 public key: %s", item.Type)
	}
}

// ItemForKey returns keyring.Item for a Key.
func ItemForKey(key Key) *keyring.Item {
	return keyring.NewItem(key.ID().String(), key.Bytes(), string(key.Type()), time.Now())
}

// KeyForItem returns Key from keyring.Item or nil if not recognized as a Key.
func KeyForItem(item *keyring.Item) (Key, error) {
	switch item.Type {
	case string(X25519):
		return x25519KeyForItem(item)
	case string(X25519Public):
		return x25519PublicKeyForItem(item)
	case string(EdX25519):
		return edx25519KeyForItem(item)
	case string(EdX25519Public):
		return edx25519PublicKeyForItem(item)
	default:
		return nil, nil
	}
}
