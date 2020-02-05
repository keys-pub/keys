package keys

import (
	"bytes"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// Keystore can saves to the keyring.
type Keystore struct {
	keyringFn KeyringFn
}

// ErrNoKeyring if no keyring is set.
var ErrNoKeyring = errors.New("no keyring set")

// NewKeystore constructs a Keystore.
func NewKeystore() *Keystore {
	return &Keystore{}
}

// NewMemKeystore returns Keystore backed by an in memory keyring.
func NewMemKeystore() *Keystore {
	ks := NewKeystore()
	ks.SetKeyring(keyring.NewMem())
	return ks
}

// SetKeyring sets the keyring.
func (k *Keystore) SetKeyring(kr keyring.Keyring) {
	k.keyringFn = func() keyring.Keyring {
		return kr
	}
}

// KeyringFn returns a keyring.
type KeyringFn func() keyring.Keyring

// SetKeyringFn sets a keyring provider.
func (k *Keystore) SetKeyringFn(keyringFn KeyringFn) {
	k.keyringFn = keyringFn
}

// Keyring ...
func (k *Keystore) Keyring() keyring.Keyring {
	if k.keyringFn == nil {
		return nil
	}
	return k.keyringFn()
}

// get returns a keyring Item for an id.
func (k *Keystore) get(id string) (*keyring.Item, error) {
	if k.Keyring() == nil {
		return nil, ErrNoKeyring
	}
	return k.Keyring().Get(id)
}

// set an item in the keyring.
func (k *Keystore) set(item *keyring.Item) error {
	if k.Keyring() == nil {
		return ErrNoKeyring
	}
	return k.Keyring().Set(item)
}

// SignKey returns sign key for a key identifier.
func (k *Keystore) SignKey(kid ID) (*SignKey, error) {
	logger.Infof("Keystore load sign key for %s", kid)
	item, err := k.get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil || item.Type != string(EdX25519) {
		return nil, nil
	}
	return AsSignKey(item)
}

// SignPublicKey returns sign public key from the Keystore.
// Since the public key itself is in the ID, you can convert the ID without
// getting it from the keystore via SignPublicKeyForID.
func (k *Keystore) SignPublicKey(kid ID) (*SignPublicKey, error) {
	logger.Infof("Keystore load sign public key for %s", kid)
	item, err := k.get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsSignPublicKey(item)
}

// BoxKey returns a box key for an identifier
func (k *Keystore) BoxKey(kid ID) (*BoxKey, error) {
	logger.Infof("Keystore load box key for %s", kid)
	item, err := k.get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil || item.Type != string(X25519) {
		return nil, nil
	}
	return AsBoxKey(item)
}

// SaveSignKey saves a SignKey to the Keystore.
func (k *Keystore) SaveSignKey(signKey *SignKey) error {
	return k.set(NewSignKeyItem(signKey))
}

// SaveSignPublicKey saves SignPublicKey to the Keystore.
func (k *Keystore) SaveSignPublicKey(spk *SignPublicKey) error {
	// Check we don't clobber an existing sign key
	item, err := k.get(spk.ID().String())
	if err != nil {
		return err
	}
	if item != nil && item.Type != string(EdX25519Public) {
		return errors.Errorf("failed to save sign public key: existing keyring item exists of alternate type")
	}
	return k.set(NewSignPublicKeyItem(spk))
}

// SaveBoxKey saves a BoxKey to the Keystore.
func (k *Keystore) SaveBoxKey(bk *BoxKey) error {
	return k.set(NewBoxKeyItem(bk))
}

// SaveBoxPublicKey saves a BoxPublicKey to the Keystore.
func (k *Keystore) SaveBoxPublicKey(bpk *BoxPublicKey) error {
	// Check we don't clobber an existing box key
	item, err := k.get(bpk.ID().String())
	if err != nil {
		return err
	}
	if item != nil && item.Type != string(X25519Public) {
		return errors.Errorf("failed to save box public key: existing keyring item exists of alternate type")
	}
	return k.set(NewBoxPublicKeyItem(bpk))
}

// Delete removes an item from the keystore.
func (k *Keystore) Delete(kid ID) (bool, error) {
	if kid == "" {
		return false, errors.Errorf("failed to delete in keystore: empty id specified")
	}
	logger.Infof("Keystore deleting: %s", kid)
	return k.Keyring().Delete(kid.String())
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
		return AsBoxKey(item)
	case string(X25519Public):
		return AsX25519PublicKey(item)
	case string(EdX25519):
		return AsSignKey(item)
	case string(EdX25519Public):
		return AsSignPublicKey(item)
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
	items, err := k.Keyring().List(&keyring.ListOpts{Types: itemTypes})
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

// BoxKeys from the Keystore.
// Also includes box keys converted from sign keys.
func (k *Keystore) BoxKeys() ([]*BoxKey, error) {
	logger.Debugf("Loading box keys...")
	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: []string{string(X25519), string(EdX25519)},
	})
	if err != nil {
		return nil, err
	}
	keys := make([]*BoxKey, 0, len(items))
	for _, item := range items {
		key, err := AsBoxKey(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	logger.Debugf("Found %d box keys", len(keys))
	return keys, nil
}

// SignKeys from the Keystore.
func (k Keystore) SignKeys() ([]*SignKey, error) {
	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: []string{string(EdX25519)},
	})
	if err != nil {
		return nil, err
	}
	keys := make([]*SignKey, 0, len(items))
	for _, item := range items {
		key, err := AsSignKey(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// SignPublicKeys from the Keystore.
// Includes public keys of SignKey's.
func (k Keystore) SignPublicKeys() ([]*SignPublicKey, error) {
	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: []string{
			string(EdX25519),
			string(EdX25519Public),
		},
	})
	if err != nil {
		return nil, err
	}
	keys := make([]*SignPublicKey, 0, len(items))
	for _, item := range items {
		switch item.Type {
		case string(EdX25519):
			key, err := AsSignKey(item)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key.PublicKey())
		case string(EdX25519Public):
			key, err := AsSignPublicKey(item)
			if err != nil {
				return nil, err
			}
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// BoxPublicKey returns box public key from the Keystore.
// Since the public key itself is in the ID, you can convert the ID without
// getting it from the keystore via BoxPublicKeyForID.
func (k *Keystore) BoxPublicKey(kid ID) (*BoxPublicKey, error) {
	logger.Infof("Keystore load box public key for %s", kid)
	item, err := k.get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsBoxPublicKey(item)
}

// SignPublicKeyForID converts ID to a sign public key.
func SignPublicKeyForID(id ID) (*SignPublicKey, error) {
	if id == "" {
		return nil, errors.Errorf("empty id")
	}
	if id.IsEdX25519() {
		return EdX25519PublicKeyFromID(id)
	}
	return nil, errors.Errorf("unrecognized id %s", id)
}

// BoxPublicKeyForID converts ID to a box public key.
// If the key is a sign key type it will convert to a box public key.
func BoxPublicKeyForID(id ID) (*BoxPublicKey, error) {
	if id == "" {
		return nil, errors.Errorf("empty id")
	}
	if id.IsX25519() {
		return X25519PublicKeyFromID(id)
	}
	if id.IsEdX25519() {
		spk, err := EdX25519PublicKeyFromID(id)
		if err != nil {
			return nil, err
		}
		return spk.X25519PublicKey(), nil
	}
	return nil, errors.Errorf("unrecognized id %s", id)
}

// FindEdX25519PublicKey searches all our EdX25519 public keys for a match to a converted
// X25519 public key.
func (k *Keystore) FindEdX25519PublicKey(bpk *X25519PublicKey) (*EdX25519PublicKey, error) {
	logger.Debugf("Finding edx25519 key from an x25519 key %s", bpk.ID())
	spks, err := k.SignPublicKeys()
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
		return k.SaveSignKey(v)
	case *X25519Key:
		return k.SaveBoxKey(v)
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
