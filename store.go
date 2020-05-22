package keys

import (
	"bytes"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// Store saves keys to the keyring.
type Store struct {
	kr *keyring.Keyring
}

// NewStore constructs a Store.
func NewStore(kr *keyring.Keyring) *Store {
	return &Store{
		kr: kr,
	}
}

// NewMemStore returns Store backed by an in memory keyring.
// This is useful for testing or ephemeral key stores.
// If setup is true, the mem keyring will be setup with a random key.
func NewMemStore(setup bool) *Store {
	mem := keyring.NewMem(setup)
	return NewStore(mem)
}

// Keyring used by Store.
func (k *Store) Keyring() *keyring.Keyring {
	return k.kr
}

// EdX25519Key returns an EdX25519Key from the keyring.
func (k *Store) EdX25519Key(kid ID) (*EdX25519Key, error) {
	logger.Infof("Store load sign key for %s", kid)
	item, err := k.kr.Get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil || item.Type != string(EdX25519) {
		return nil, nil
	}
	return AsEdX25519Key(item)
}

// EdX25519PublicKey returns EdX25519 public key from the keyring.
// Since the public key itself is in the ID, you can convert the ID without
// getting it from the Store via NewEdX25519PublicKeyFromID.
func (k *Store) EdX25519PublicKey(kid ID) (*EdX25519PublicKey, error) {
	logger.Infof("Store load EdX25519 public key for %s", kid)
	item, err := k.kr.Get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsEdX25519PublicKey(item)
}

// X25519Key returns an X25519Key from the keyring.
func (k *Store) X25519Key(kid ID) (*X25519Key, error) {
	logger.Infof("Store load box key for %s", kid)
	item, err := k.kr.Get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil || item.Type != string(X25519) {
		return nil, nil
	}
	return AsX25519Key(item)
}

// Save saves a Key to the keyring.
// Returns keyring.ErrItemAlreadyExists if key exists already.
func (k *Store) Save(key Key) error {
	return k.kr.Create(ItemForKey(key))
}

// Delete removes an item from the keyring.
func (k *Store) Delete(kid ID) (bool, error) {
	if kid == "" {
		return false, errors.Errorf("failed to delete: empty id")
	}
	logger.Infof("Store deleting: %s", kid)
	return k.kr.Delete(kid.String())
}

// Key for id.
func (k *Store) Key(id ID) (Key, error) {
	item, err := k.kr.Get(id.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return keyForItem(item)
}

// keyForItem returns Key or nil if not recognized as a key.
func keyForItem(item *keyring.Item) (Key, error) {
	switch item.Type {
	case string(X25519):
		return AsX25519Key(item)
	case string(X25519Public):
		return AsX25519PublicKey(item)
	case string(EdX25519):
		return AsEdX25519Key(item)
	case string(EdX25519Public):
		return AsEdX25519PublicKey(item)
	default:
		return nil, nil
	}
}

// Opts are options for listing keys.
type Opts struct {
	Types []KeyType
}

// Keys lists keys in the keyring.
// It ignores keyring items that aren't keys or of the specified types.
func (k *Store) Keys(opts *Opts) ([]Key, error) {
	if opts == nil {
		opts = &Opts{}
	}
	logger.Debugf("Keys %+v", opts)
	itemTypes := make([]string, 0, len(opts.Types))
	for _, t := range opts.Types {
		itemTypes = append(itemTypes, string(t))
	}
	items, err := k.kr.List(keyring.WithTypes(itemTypes...))
	if err != nil {
		return nil, err
	}
	keys := make([]Key, 0, len(items))
	for _, item := range items {
		// logger.Debugf("Key for item type: %s", item.Type)
		key, err := keyForItem(item)
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
func (k *Store) X25519Keys() ([]*X25519Key, error) {
	logger.Debugf("Listing x25519 keys...")
	items, err := k.kr.List(keyring.WithTypes(string(X25519), string(EdX25519)))
	if err != nil {
		return nil, err
	}
	keys := make([]*X25519Key, 0, len(items))
	for _, item := range items {
		key, err := AsX25519Key(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	logger.Debugf("Found %d x25519 keys", len(keys))
	return keys, nil
}

// EdX25519Keys from the keyring.
func (k *Store) EdX25519Keys() ([]*EdX25519Key, error) {
	items, err := k.kr.List(keyring.WithTypes(string(EdX25519)))
	if err != nil {
		return nil, err
	}
	keys := make([]*EdX25519Key, 0, len(items))
	for _, item := range items {
		key, err := AsEdX25519Key(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// EdX25519PublicKeys from the keyring.
// Includes public keys of EdX25519Key's.
func (k *Store) EdX25519PublicKeys() ([]*EdX25519PublicKey, error) {
	items, err := k.kr.List(keyring.WithTypes(string(EdX25519), string(EdX25519Public)))
	if err != nil {
		return nil, err
	}
	keys := make([]*EdX25519PublicKey, 0, len(items))
	for _, item := range items {
		switch item.Type {
		case string(EdX25519):
			key, err := AsEdX25519Key(item)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key.PublicKey())
		case string(EdX25519Public):
			key, err := AsEdX25519PublicKey(item)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// X25519PublicKey returns box public key from the keyring.
// Since the public key itself is in the ID, you can convert the ID without
// getting it from the Store via X25519PublicKeyForID.
func (k *Store) X25519PublicKey(kid ID) (*X25519PublicKey, error) {
	logger.Infof("Store load box public key for %s", kid)
	item, err := k.kr.Get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsX25519PublicKey(item)
}

// FindEdX25519PublicKey searches all our EdX25519 public keys for a match to a converted
// X25519 public key.
func (k *Store) FindEdX25519PublicKey(kid ID) (*EdX25519PublicKey, error) {
	logger.Debugf("Finding edx25519 key from an x25519 key %s", kid)
	spks, err := k.EdX25519PublicKeys()
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
func (k *Store) ImportSaltpack(msg string, password string, isHTML bool) (Key, error) {
	key, err := DecodeKeyFromSaltpack(msg, password, isHTML)
	if err != nil {
		return nil, err
	}
	if err := k.Save(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ExportSaltpack exports key from the keyring to a Saltpack message.
func (k *Store) ExportSaltpack(id ID, password string) (string, error) {
	key, err := k.Key(id)
	if err != nil {
		return "", err
	}
	return EncodeKeyToSaltpack(key, password)
}
