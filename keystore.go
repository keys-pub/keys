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

// Get returns a keyring Item for an id.
func (k *Keystore) Get(id string) (*keyring.Item, error) {
	if k.Keyring() == nil {
		return nil, ErrNoKeyring
	}
	return k.Keyring().Get(id)
}

// Set an item in the keyring.
func (k *Keystore) Set(item *keyring.Item) error {
	if k.Keyring() == nil {
		return ErrNoKeyring
	}
	return k.Keyring().Set(item)
}

// List returns items in the keyring.
func (k *Keystore) List() ([]*keyring.Item, error) {
	if k.Keyring() == nil {
		return nil, ErrNoKeyring
	}
	return k.Keyring().List(nil)
}

// SecretKey returns secret key for an identifier
func (k *Keystore) SecretKey(kid ID) (SecretKey, error) {
	logger.Debugf("Keystore load secret key for %s", kid)
	item, err := k.Get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsSecretKey(item)
}

// SignKey returns sign key for a key identifier.
func (k *Keystore) SignKey(kid ID) (*SignKey, error) {
	logger.Infof("Keystore load sign key for %s", kid)
	item, err := k.Get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsSignKey(item)
}

// BoxKey returns a box key for an identifier
func (k *Keystore) BoxKey(kid ID) (*BoxKey, error) {
	logger.Infof("Keystore load box key for %s", kid)
	item, err := k.Get(kid.String())
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}

	if item.Type == BoxKeyringType {
		return AsBoxKey(item)
	}

	if item.Type == SignKeyringType {
		sk, err := AsSignKey(item)
		if err != nil {
			return nil, err
		}
		return sk.BoxKey()
	}

	return nil, errors.Errorf("invalid box key type")
}

// CertificateKey for identifier.
func (k *Keystore) CertificateKey(id string) (*CertificateKey, error) {
	logger.Debugf("Keystore load certificate key for %s", id)
	item, err := k.Get(id)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsCertificateKey(item)
}

// SaveSecretKey saves a secret key to the Keystore.
func (k *Keystore) SaveSecretKey(kid string, secretKey *[32]byte) error {
	return k.Set(NewSecretKeyItem(kid, secretKey))
}

// SaveSignKey saves a nacl.sign SignKey to the Keystore.
func (k *Keystore) SaveSignKey(signKey *SignKey) error {
	return k.Set(NewSignKeyItem(signKey))
}

// SaveBoxKey saves a nacl.box BoxKey to the Keystore.
func (k *Keystore) SaveBoxKey(boxKey *BoxKey) error {
	return k.Set(NewBoxKeyItem(boxKey))
}

// SavePassphrase saves a passphrase to the Keystore.
func (k *Keystore) SavePassphrase(id string, passphrase string) error {
	return k.Set(NewPassphraseItem(id, passphrase))
}

// SaveCertificateKey saves a certificate key to the Keystore.
func (k *Keystore) SaveCertificateKey(id string, cert *CertificateKey) error {
	return k.Set(NewCertificateKeyItem(id, cert.Private(), cert.Public()))
}

// Delete removes an item from the keystore.
func (k *Keystore) Delete(id string) (bool, error) {
	if id == "" {
		return false, errors.Errorf("failed to delete in keystore: empty id specified")
	}
	logger.Infof("Keystore deleting: %s", id)
	return k.Keyring().Delete(id)
}

// BoxKeys from the Keystore.
func (k *Keystore) BoxKeys() ([]*BoxKey, error) {
	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: []string{BoxKeyringType},
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
		bk, err := sk.BoxKey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, bk)
	}

	return keys, nil
}

// SignKeys from the Keystore.
func (k Keystore) SignKeys() ([]*SignKey, error) {
	items, err := k.Keyring().List(&keyring.ListOpts{
		Types: []string{SignKeyringType},
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

// BoxPublicKeyFromID gets box public key for an ID.
func (k *Keystore) BoxPublicKeyFromID(id ID) (BoxPublicKey, error) {
	if id == "" {
		return nil, errors.Errorf("empty")
	}

	hrp, _, err := id.Decode()
	if err != nil {
		return nil, err
	}

	switch hrp {
	case BoxKeyType:
		bpk, err := boxPublicKeyFromID(id)
		if err != nil {
			return nil, err
		}
		return bpk, nil
	case SignKeyType:
		spk, err := signPublicKeyFromID(id)
		if err != nil {
			return nil, err
		}
		return spk.BoxPublicKey(), nil

	default:
		return nil, errors.Errorf("unrecognized %s", id)
	}
}
