package keys

import (
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
	if item == nil || item.Type != string(SignItemType) {
		return nil, nil
	}
	return AsSignKey(item)
}

// SignPublicKey returns sign public key for a key identifier.
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
	if item == nil || item.Type != string(BoxItemType) {
		return nil, nil
	}
	return AsBoxKey(item)
}

// SaveSignKey saves a SignKey to the Keystore.
func (k *Keystore) SaveSignKey(signKey *SignKey) error {
	return k.set(NewSignKeyItem(signKey))
}

// SaveSignPublicKey saves
func (k *Keystore) SaveSignPublicKey(spk *SignPublicKey) error {
	// Check we don't clobber an existing sign key
	item, err := k.get(spk.ID().String())
	if err != nil {
		return err
	}
	if item != nil && item.Type != string(SignPublicItemType) {
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
	if item != nil && item.Type != string(BoxPublicItemType) {
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

// BoxKeys from the Keystore.
// Also includes box keys converted from sign keys.
func (k *Keystore) BoxKeys() ([]*BoxKey, error) {
	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: []string{string(BoxItemType)},
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

	// Include box keys converted from sign keys.
	sks, err := k.SignKeys()
	if err != nil {
		return nil, err
	}
	for _, sk := range sks {
		bk := sk.BoxKey()
		keys = append(keys, bk)
	}

	return keys, nil
}

// SignKeys from the Keystore.
func (k Keystore) SignKeys() ([]*SignKey, error) {
	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: []string{string(SignItemType)},
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
func (k Keystore) SignPublicKeys() ([]*SignPublicKey, error) {
	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: []string{string(SignPublicItemType)},
	})
	if err != nil {
		return nil, err
	}
	keys := make([]*SignPublicKey, 0, len(items))
	for _, item := range items {
		key, err := AsSignPublicKey(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// Keys is the result from Keys.
type Keys struct {
	SignKeys       []*SignKey
	SignPublicKeys []*SignPublicKey
	BoxKeys        []*BoxKey
	BoxPublicKeys  []*BoxPublicKey
}

// Capacity of all the keys.
func (k Keys) Capacity() int {
	return len(k.SignKeys) + len(k.SignPublicKeys) + len(k.BoxKeys) + len(k.BoxPublicKeys)
}

// Keys for types.
func (k Keystore) Keys(types []ItemType) (*Keys, error) {
	stypes := make([]string, 0, len(types))
	for _, t := range types {
		stypes = append(stypes, string(t))
	}

	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: stypes,
	})
	if err != nil {
		return nil, err
	}
	sks := make([]*SignKey, 0, len(items))
	spks := make([]*SignPublicKey, 0, len(items))
	bks := make([]*BoxKey, 0, len(items))
	bpks := make([]*BoxPublicKey, 0, len(items))
	for _, item := range items {
		switch ItemType(item.Type) {
		case SignItemType:
			sk, err := AsSignKey(item)
			if err != nil {
				return nil, err
			}
			sks = append(sks, sk)
		case SignPublicItemType:
			spk, err := AsSignPublicKey(item)
			if err != nil {
				return nil, err
			}
			spks = append(spks, spk)
		case BoxItemType:
			bk, err := AsBoxKey(item)
			if err != nil {
				return nil, err
			}
			bks = append(bks, bk)
		case BoxPublicItemType:
			bpk, err := AsBoxPublicKey(item)
			if err != nil {
				return nil, err
			}
			bpks = append(bpks, bpk)
		default:
			return nil, errors.Errorf("item type for list not supported yet %s", item.Type)
		}
	}
	return &Keys{
		SignKeys:       sks,
		SignPublicKeys: spks,
		BoxKeys:        bks,
		BoxPublicKeys:  bpks,
	}, nil
}

// BoxPublicKey gets box public key for an ID.
// If key is a sign public key will convert to a box public key.
func (k *Keystore) BoxPublicKey(id ID) (*BoxPublicKey, error) {
	if id == "" {
		return nil, errors.Errorf("empty")
	}

	hrp, _, err := id.Decode()
	if err != nil {
		return nil, err
	}

	switch hrp {
	case string(BoxKeyType):
		bpk, err := boxPublicKeyFromID(id)
		if err != nil {
			return nil, err
		}
		return bpk, nil
	case string(SignKeyType):
		spk, err := SignPublicKeyFromID(id)
		if err != nil {
			return nil, err
		}
		return spk.BoxPublicKey(), nil

	default:
		return nil, errors.Errorf("unrecognized %s", id)
	}
}
