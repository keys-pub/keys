package keys

import (
	"bytes"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// Keystore can saves to the keyring.
type Keystore struct {
	kr keyring.Keyring
}

// ErrNoKeyring if no keyring is set.
var ErrNoKeyring = errors.New("no keyring set")

// NewKeystore constructs a Keystore.
func NewKeystore(kr keyring.Keyring) *Keystore {
	return &Keystore{
		kr: kr,
	}
}

// Keyring for Keystore.
func (k *Keystore) Keyring() (keyring.Keyring, error) {
	if k.kr == nil {
		return nil, ErrNoKeyring
	}
	return k.kr, nil
}

// NewMemKeystore returns Keystore backed by an in memory keyring.
// This is useful for testing or ephemeral key stores.
func NewMemKeystore() *Keystore {
	return NewKeystore(keyring.NewMem())
}

// get returns a keyring Item for an id.
func (k *Keystore) get(id string) (*keyring.Item, error) {
	if k.kr == nil {
		return nil, ErrNoKeyring
	}
	return k.kr.Get(id)
}

// set an item in the keyring.
func (k *Keystore) set(item *keyring.Item) error {
	if k.kr == nil {
		return ErrNoKeyring
	}
	return k.kr.Set(item)
}

// EdX25519Key returns sign key for a key identifier.
func (k *Keystore) EdX25519Key(kid ID) (*EdX25519Key, error) {
	logger.Infof("Keystore load sign key for %s", kid)
	item, err := k.get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil || item.Type != string(EdX25519) {
		return nil, nil
	}
	return AsEdX25519Key(item)
}

// EdX25519PublicKey returns sign public key from the Keystore.
// Since the public key itself is in the ID, you can convert the ID without
// getting it from the keystore via NewEdX25519PublicKeyFromID.
func (k *Keystore) EdX25519PublicKey(kid ID) (*EdX25519PublicKey, error) {
	logger.Infof("Keystore load sign public key for %s", kid)
	item, err := k.get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsEdX25519PublicKey(item)
}

// X25519Key returns a box key for an identifier
func (k *Keystore) X25519Key(kid ID) (*X25519Key, error) {
	logger.Infof("Keystore load box key for %s", kid)
	item, err := k.get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil || item.Type != string(X25519) {
		return nil, nil
	}
	return AsX25519Key(item)
}

// SavePublicKey saves a public key from a key identifier.
func (k *Keystore) SavePublicKey(kid ID) error {
	hrp, b, err := kid.Decode()
	if err != nil {
		return err
	}
	switch hrp {
	case x25519KeyHRP:
		if len(b) != 32 {
			return errors.Errorf("invalid id public key bytes")
		}
		bpk := NewX25519PublicKey(Bytes32(b))
		return k.SaveX25519PublicKey(bpk)
	case edx25519KeyHRP:
		if len(b) != 32 {
			return errors.Errorf("invalid id public key bytes")
		}
		spk := NewEdX25519PublicKey(Bytes32(b))
		return k.SaveEdX25519PublicKey(spk)
	default:
		return errors.Errorf("unrecognized key type")
	}
}

// SaveEdX25519Key saves a EdX25519Key to the Keystore.
func (k *Keystore) SaveEdX25519Key(signKey *EdX25519Key) error {
	return k.set(NewEdX25519KeyItem(signKey))
}

// SaveEdX25519PublicKey saves EdX25519PublicKey to the Keystore.
func (k *Keystore) SaveEdX25519PublicKey(spk *EdX25519PublicKey) error {
	// Check we don't clobber an existing sign key
	item, err := k.get(spk.ID().String())
	if err != nil {
		return err
	}
	if item != nil && item.Type != string(EdX25519Public) {
		return errors.Errorf("failed to save sign public key: existing keyring item exists of alternate type")
	}
	return k.set(NewEdX25519PublicKeyItem(spk))
}

// SaveX25519Key saves a X25519Key to the Keystore.
func (k *Keystore) SaveX25519Key(bk *X25519Key) error {
	return k.set(NewX25519KeyItem(bk))
}

// SaveX25519PublicKey saves a X25519PublicKey to the Keystore.
func (k *Keystore) SaveX25519PublicKey(bpk *X25519PublicKey) error {
	// Check we don't clobber an existing box key
	item, err := k.get(bpk.ID().String())
	if err != nil {
		return err
	}
	if item != nil && item.Type != string(X25519Public) {
		return errors.Errorf("failed to save box public key: existing keyring item exists of alternate type")
	}
	return k.set(NewX25519PublicKeyItem(bpk))
}

// Delete removes an item from the keystore.
func (k *Keystore) Delete(kid ID) (bool, error) {
	if kid == "" {
		return false, errors.Errorf("failed to delete in keystore: empty id specified")
	}
	logger.Infof("Keystore deleting: %s", kid)
	kr, err := k.Keyring()
	if err != nil {
		return false, err
	}
	return kr.Delete(kid.String())
}

// Key for id.
func (k *Keystore) Key(id ID) (Key, error) {
	item, err := k.get(id.String())
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
func (k *Keystore) Keys(opts *Opts) ([]Key, error) {
	if opts == nil {
		opts = &Opts{}
	}
	logger.Debugf("Keys %+v", opts)
	itemTypes := make([]string, 0, len(opts.Types)*2)
	for _, t := range opts.Types {
		itemTypes = append(itemTypes, string(t))
	}
	kr, err := k.Keyring()
	if err != nil {
		return nil, err
	}
	items, err := kr.List(&keyring.ListOpts{Types: itemTypes})
	if err != nil {
		return nil, err
	}
	keys := make([]Key, 0, len(items))
	for _, item := range items {
		logger.Debugf("Key for item type: %s", item.Type)
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

// X25519Keys from the Keystore.
// Also includes edx25519 keys converted to x25519 keys.
func (k *Keystore) X25519Keys() ([]*X25519Key, error) {
	logger.Debugf("Loading x25519 keys...")
	kr, err := k.Keyring()
	if err != nil {
		return nil, err
	}
	items, err := kr.List(&keyring.ListOpts{
		Types: []string{string(X25519), string(EdX25519)},
	})
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

// EdX25519Keys from the Keystore.
func (k Keystore) EdX25519Keys() ([]*EdX25519Key, error) {
	kr, err := k.Keyring()
	if err != nil {
		return nil, err
	}
	items, err := kr.List(&keyring.ListOpts{
		Types: []string{string(EdX25519)},
	})
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

// EdX25519PublicKeys from the Keystore.
// Includes public keys of EdX25519Key's.
func (k Keystore) EdX25519PublicKeys() ([]*EdX25519PublicKey, error) {
	kr, err := k.Keyring()
	if err != nil {
		return nil, err
	}
	items, err := kr.List(&keyring.ListOpts{
		Types: []string{
			string(EdX25519),
			string(EdX25519Public),
		},
	})
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

// X25519PublicKey returns box public key from the Keystore.
// Since the public key itself is in the ID, you can convert the ID without
// getting it from the keystore via X25519PublicKeyForID.
func (k *Keystore) X25519PublicKey(kid ID) (*X25519PublicKey, error) {
	logger.Infof("Keystore load box public key for %s", kid)
	item, err := k.get(kid.String())
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
func (k *Keystore) FindEdX25519PublicKey(kid ID) (*EdX25519PublicKey, error) {
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

// SaveKey saves Key based on its type.
func (k *Keystore) SaveKey(key Key) error {
	switch v := key.(type) {
	case *EdX25519Key:
		return k.SaveEdX25519Key(v)
	case *X25519Key:
		return k.SaveX25519Key(v)
	default:
		return errors.Errorf("unsupported key")
	}
}

// ImportSaltpack imports key into the keystore from a saltpack message.
func (k *Keystore) ImportSaltpack(msg string, password string, isHTML bool) (Key, error) {
	key, err := DecodeKeyFromSaltpack(msg, password, isHTML)
	if err != nil {
		return nil, err
	}
	if err := k.SaveKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ExportSaltpack exports key from the keystore to a saltpack message.
func (k *Keystore) ExportSaltpack(id ID, password string) (string, error) {
	key, err := k.Key(id)
	if err != nil {
		return "", err
	}
	return EncodeKeyToSaltpack(key, password)
}
