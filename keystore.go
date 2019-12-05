package keys

import (
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// Keystore can create, update, and search for keys, and include public key
// stores.
type Keystore struct {
	keyringFn KeyringFn
	scs       SigchainStore
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

// SetSigchainStore sets the sigchain store.
func (k *Keystore) SetSigchainStore(scs SigchainStore) {
	k.scs = scs
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
func (k *Keystore) Get(id ID) (*keyring.Item, error) {
	if k.Keyring() == nil {
		return nil, ErrNoKeyring
	}
	return k.Keyring().Get(id.String())
}

// Set an item in the keyring.
func (k *Keystore) Set(item *keyring.Item) error {
	if k.Keyring() == nil {
		return ErrNoKeyring
	}
	return k.Keyring().Set(item)
}

// List returns items in the keyring.
func (k *Keystore) List(opts *keyring.ListOpts) ([]*keyring.Item, error) {
	if k.Keyring() == nil {
		return nil, ErrNoKeyring
	}
	if opts == nil {
		opts = &keyring.ListOpts{}
	}
	return k.Keyring().List(opts)
}

// SecretKey returns secret key for an identifier
func (k *Keystore) SecretKey(kid ID) (SecretKey, error) {
	logger.Debugf("Keystore load secret key for %s", kid)
	item, err := k.Get(kid)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsSecretKey(item)
}

// AsSecretKey returns SecretKey for keyring Item.
func AsSecretKey(item *keyring.Item) (SecretKey, error) {
	if item.Type != SecretKeyType {
		return nil, errors.Errorf("item type %s != %s", item.Type, SecretKeyType)
	}
	return Bytes32(item.SecretData()), nil
}

// SignKey returns sign key for a key identifier.
func (k *Keystore) SignKey(kid ID) (*SignKey, error) {
	logger.Infof("Keystore load sign key for %s", kid)
	item, err := k.Get(kid)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsSignKey(item)
}

// AsSignKey returns SignKey for keyring Item.
func AsSignKey(item *keyring.Item) (*SignKey, error) {
	if item.Type != SignKeyType {
		return nil, errors.Errorf("item type %s != %s", item.Type, SignKeyType)
	}
	sk, err := NewSignKey(item.SecretData())
	if err != nil {
		return nil, err
	}
	return sk, nil
}

// BoxKey returns a box key for an identifier
func (k *Keystore) BoxKey(kid ID) (*BoxKey, error) {
	logger.Infof("Keystore load box key for %s", kid)
	item, err := k.Get(kid)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsBoxKey(item)
}

// AsBoxKey returns BoxKey for keyring Item.
func AsBoxKey(item *keyring.Item) (*BoxKey, error) {
	if item.Type != BoxKeyType {
		return nil, errors.Errorf("item type %s != %s", item.Type, BoxKeyType)
	}
	boxKey := NewBoxKeyFromPrivateKey(Bytes32(item.SecretData()))
	return boxKey, nil
}

// CertificateKey for identifier.
func (k *Keystore) CertificateKey(id ID) (*CertificateKey, error) {
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

// AsCertificateKey returns CertificateKey for keyring Item.
func AsCertificateKey(item *keyring.Item) (*CertificateKey, error) {
	if item.Type != CertificateKeyType {
		return nil, errors.Errorf("item type %s != %s", item.Type, CertificateKeyType)
	}
	private := string(item.SecretData())
	public := string(item.SecretDataFor("public"))
	return NewCertificateKey(private, public)
}

// SaveSecretKey saves a secret key to the Keystore.
func (k *Keystore) SaveSecretKey(kid ID, secretKey SecretKey) error {
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
func (k *Keystore) SavePassphrase(id ID, passphrase string) error {
	return k.Set(NewPassphraseItem(id.String(), passphrase))
}

// SaveCertificateKey saves a certificate key to the Keystore.
func (k *Keystore) SaveCertificateKey(id ID, cert *CertificateKey) error {
	return k.Set(NewCertificateKeyItem(id.String(), cert.Private(), cert.Public()))
}

// Delete removes an item from the keystore.
func (k *Keystore) Delete(id string) (bool, error) {
	if id == "" {
		return false, errors.Errorf("failed to delete in keystore: empty id specified")
	}
	logger.Infof("Keystore deleting: %s", id)
	return k.Keyring().Delete(id)
}

// GenerateSecretKey generates and saves a SecretKey to the Keystore.
func (k *Keystore) GenerateSecretKey(kid ID) (SecretKey, error) {
	secretKey := GenerateSecretKey()
	if err := k.SaveSecretKey(kid, secretKey); err != nil {
		return nil, err
	}
	return secretKey, nil
}

// GenerateSignKey generates and saves a SignKey to the Keystore.
func (k *Keystore) GenerateSignKey() (*SignKey, error) {
	signKey := GenerateSignKey()
	if err := k.SaveSignKey(signKey); err != nil {
		return nil, err
	}
	return signKey, nil
}

// GenerateBoxKey generates and saves a BoxKey to the Keystore.
func (k *Keystore) GenerateBoxKey() (*BoxKey, error) {
	boxKey := GenerateBoxKey()
	if err := k.SaveBoxKey(boxKey); err != nil {
		return nil, err
	}
	return boxKey, nil
}

// PublicKey returns a PublicKey (from a Sigchain).
func (k Keystore) PublicKey(kid ID) (PublicKey, error) {
	logger.Debugf("Keystore sigchain %s", kid)
	if k.scs == nil {
		return nil, errors.Errorf("no sigchain store")
	}
	sk, err := k.scs.Sigchain(kid)
	if err != nil {
		return nil, err
	}
	if sk == nil {
		return nil, nil
	}
	return sk, nil
}

// GenerateKey generates and saves key material to the keystore.
func (k *Keystore) GenerateKey(generateSigchain bool, ts time.Time) (Key, error) {
	key := GenerateKey()
	if err := k.SaveKey(key, generateSigchain, ts); err != nil {
		return nil, err
	}
	return key, nil
}

// Key returns key.
func (k *Keystore) Key(id ID) (Key, error) {
	logger.Debugf("Keystore load key for %s", id)
	item, err := k.Get(id)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return AsKey(item)
}

// SaveKey saves key.
func (k *Keystore) SaveKey(key Key, generateSigchain bool, ts time.Time) error {
	if generateSigchain {
		if k.scs == nil {
			return errors.Errorf("no sigchain store set")
		}
		if err := k.scs.SaveSigchain(GenerateSigchain(key, ts)); err != nil {
			return err
		}
	}
	return k.Set(NewKeyItem(key))
}

// AsKey return Key from keyring.Item.
func AsKey(item *keyring.Item) (Key, error) {
	if item.Type != KeyType {
		return nil, errors.Errorf("item type %s != %s", item.Type, KeyType)
	}
	b := item.SecretData()
	if len(b) != 32 {
		return nil, errors.Errorf("invalid key bytes")
	}
	return NewKey(Bytes32(b))
}

// Keys returns all keys in the Keystore.
func (k Keystore) Keys() ([]Key, error) {
	items, err := k.Keyring().List(&keyring.ListOpts{
		Type: KeyType,
	})
	if err != nil {
		return nil, err
	}
	keys := make([]Key, 0, len(items))
	for _, item := range items {
		key, err := AsKey(item)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}
