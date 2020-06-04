package keys

import (
	"bytes"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

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

// Find returns Key for id.
func Find(kr *keyring.Keyring, id ID) (Key, error) {
	item, err := kr.Get(id.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return KeyForItem(item)
}

// FindEdX25519Key returns EdX25519Key for id.
func FindEdX25519Key(kr *keyring.Keyring, id ID) (*EdX25519Key, error) {
	key, err := Find(kr, id)
	if err != nil {
		return nil, err
	}
	sk, ok := key.(*EdX25519Key)
	if !ok {
		return nil, nil
	}
	return sk, nil
}

// FindX25519Key returns X25519Key for id.
func FindX25519Key(kr *keyring.Keyring, id ID) (*X25519Key, error) {
	key, err := Find(kr, id)
	if err != nil {
		return nil, err
	}
	bk, ok := key.(*X25519Key)
	if !ok {
		return nil, nil
	}
	return bk, nil
}

// Save key to keyring.
func Save(kr *keyring.Keyring, key Key) error {
	return kr.Create(ItemForKey(key))
}

// Delete key from keyring.
func Delete(kr *keyring.Keyring, id ID) (bool, error) {
	return kr.Delete(id.String())
}

// Options ...
type Options struct {
	Types []KeyType
}

// Option ...
type Option func(*Options) error

func newOptions(opts ...Option) (Options, error) {
	var options Options
	for _, o := range opts {
		if err := o(&options); err != nil {
			return options, err
		}
	}
	return options, nil
}

// WithTypes ...
func WithTypes(types ...KeyType) Option {
	return func(o *Options) error {
		o.Types = types
		return nil
	}
}

// Keys lists keys in the keyring.
// It ignores keyring items that aren't keys or of the specified types.
func Keys(kr *keyring.Keyring, opt ...Option) ([]Key, error) {
	opts, err := newOptions(opt...)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Keys %+v", opts)
	itemTypes := make([]string, 0, len(opts.Types))
	for _, t := range opts.Types {
		itemTypes = append(itemTypes, string(t))
	}
	items, err := kr.List(keyring.WithTypes(itemTypes...))
	if err != nil {
		return nil, err
	}
	keys := make([]Key, 0, len(items))
	for _, item := range items {
		// logger.Debugf("Key for item type: %s", item.Type)
		key, err := KeyForItem(item)
		if err != nil {
			return nil, err
		}
		if key == nil {
			continue
		}
		keys = append(keys, key)
	}
	logger.Debugf("Found %d keys", len(keys))
	return keys, nil
}

// X25519Keys from the keyring.
// Also includes edx25519 keys converted to x25519 keys.
func X25519Keys(kr *keyring.Keyring) ([]*X25519Key, error) {
	logger.Debugf("Listing x25519 keys...")
	items, err := kr.List(keyring.WithTypes(string(X25519), string(EdX25519)))
	if err != nil {
		return nil, err
	}
	keys := make([]*X25519Key, 0, len(items))
	for _, item := range items {
		key, err := x25519KeyForItem(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	logger.Debugf("Found %d x25519 keys", len(keys))
	return keys, nil
}

// EdX25519Keys from the keyring.
func EdX25519Keys(kr *keyring.Keyring) ([]*EdX25519Key, error) {
	items, err := kr.List(keyring.WithTypes(string(EdX25519)))
	if err != nil {
		return nil, err
	}
	keys := make([]*EdX25519Key, 0, len(items))
	for _, item := range items {
		key, err := edx25519KeyForItem(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// EdX25519PublicKeys from the keyring.
// Includes public keys of EdX25519Key's.
func EdX25519PublicKeys(kr *keyring.Keyring) ([]*EdX25519PublicKey, error) {
	items, err := kr.List(keyring.WithTypes(string(EdX25519), string(EdX25519Public)))
	if err != nil {
		return nil, err
	}
	keys := make([]*EdX25519PublicKey, 0, len(items))
	for _, item := range items {
		switch item.Type {
		case string(EdX25519):
			key, err := edx25519KeyForItem(item)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key.PublicKey())
		case string(EdX25519Public):
			key, err := edx25519PublicKeyForItem(item)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// FindEdX25519PublicKey searches all our EdX25519 public keys for a match to a converted
// X25519 public key.
func FindEdX25519PublicKey(kr *keyring.Keyring, kid ID) (*EdX25519PublicKey, error) {
	logger.Debugf("Finding edx25519 key from an x25519 key %s", kid)
	spks, err := EdX25519PublicKeys(kr)
	if err != nil {
		return nil, err
	}
	bpk, err := NewX25519PublicKeyFromID(kid)
	if err != nil {
		return nil, err
	}
	for _, spk := range spks {
		if bytes.Equal(spk.X25519PublicKey().Bytes(), bpk.Bytes()) {
			logger.Debugf("Found ed25519 key %s", spk.ID())
			return spk, nil
		}
	}
	logger.Debugf("EdX25519 key not found")
	return nil, err
}

// ImportSaltpack imports key into the keyring from a Saltpack message.
func ImportSaltpack(kr *keyring.Keyring, msg string, password string, isHTML bool) (Key, error) {
	key, err := DecodeKeyFromSaltpack(msg, password, isHTML)
	if err != nil {
		return nil, err
	}
	if err := kr.Create(ItemForKey(key)); err != nil {
		return nil, err
	}
	return key, nil
}

// ExportSaltpack exports key from the keyring to a Saltpack message.
func ExportSaltpack(kr *keyring.Keyring, id ID, password string) (string, error) {
	key, err := Find(kr, id)
	if err != nil {
		return "", err
	}
	return EncodeKeyToSaltpack(key, password)
}

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
