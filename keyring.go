package keys

import (
	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// ItemType for is type for keyring items.
type ItemType string

const (
	// SignItemType ...
	SignItemType ItemType = "sign-key"
	// SignPublicItemType ...
	SignPublicItemType ItemType = "sign-public-key"
	// BoxItemType ...
	BoxItemType ItemType = "box-key"
	// BoxPublicItemType ...
	BoxPublicItemType ItemType = "box-public-key"
	// CertificateItemType ...
	CertificateItemType ItemType = "cert-key"
	// PassphraseItemType ...
	PassphraseItemType ItemType = "passphrase"
	// SecretItemType ...
	SecretItemType ItemType = "secret"
)

// NewBoxKeyItem creates keyring item for BoxKey.
func NewBoxKeyItem(boxKey *BoxKey) *keyring.Item {
	return keyring.NewItem(boxKey.ID().String(), keyring.NewSecret(boxKey.PrivateKey()[:]), string(BoxItemType))
}

// AsBoxKey returns BoxKey for keyring Item.
func AsBoxKey(item *keyring.Item) (*BoxKey, error) {
	if item.Type != string(BoxItemType) {
		return nil, errors.Errorf("item type %s != %s", item.Type, BoxItemType)
	}
	boxKey := NewBoxKeyFromPrivateKey(Bytes32(item.SecretData()))
	return boxKey, nil
}

// NewSignKeyItem creates keyring item for SignKey.
func NewSignKeyItem(signKey *SignKey) *keyring.Item {
	return keyring.NewItem(signKey.ID().String(), keyring.NewSecret(signKey.PrivateKey()[:]), string(SignItemType))
}

// AsSignKey returns SignKey for keyring Item.
func AsSignKey(item *keyring.Item) (*SignKey, error) {
	if item.Type != string(SignItemType) {
		return nil, errors.Errorf("item type %s != %s", item.Type, SignItemType)
	}
	sk, err := NewSignKeyFromPrivateKey(item.SecretData())
	if err != nil {
		return nil, err
	}
	return sk, nil
}

// NewSignPublicKeyItem creates keyring item for SignPublicKey.
func NewSignPublicKeyItem(publicKey *SignPublicKey) *keyring.Item {
	return keyring.NewItem(publicKey.ID().String(), keyring.NewSecret(publicKey.Bytes()[:]), string(SignPublicItemType))
}

// AsSignPublicKey returns SignPublicKey for keyring Item.
func AsSignPublicKey(item *keyring.Item) (*SignPublicKey, error) {
	switch item.Type {
	case string(SignPublicItemType):
		return NewSignPublicKey(Bytes32(item.SecretData())), nil
	case string(SignItemType):
		sk, err := AsSignKey(item)
		if err != nil {
			return nil, err
		}
		return sk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for sign public key: %s", item.Type)
	}
}

// NewBoxPublicKeyItem creates keyring item for BoxPublicKey.
func NewBoxPublicKeyItem(publicKey *BoxPublicKey) *keyring.Item {
	return keyring.NewItem(publicKey.ID().String(), keyring.NewSecret(publicKey.Bytes()[:]), string(BoxPublicItemType))
}

// AsBoxPublicKey returns BoxPublicKey for keyring Item.
func AsBoxPublicKey(item *keyring.Item) (*BoxPublicKey, error) {
	switch item.Type {
	case string(BoxPublicItemType):
		return NewBoxPublicKey(Bytes32(item.SecretData())), nil
	case string(BoxItemType):
		bk, err := AsBoxKey(item)
		if err != nil {
			return nil, err
		}
		return bk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for box public key: %s", item.Type)
	}
}

// NewSecretKeyItem creates keyring item for SecretKey.
func NewSecretKeyItem(kid string, secretKey SecretKey) *keyring.Item {
	return keyring.NewItem(kid, keyring.NewSecret(secretKey[:]), string(SecretItemType))
}

// AsSecretKey returns SecretKey for keyring Item.
func AsSecretKey(item *keyring.Item) (SecretKey, error) {
	if item.Type != string(SecretItemType) {
		return nil, errors.Errorf("item type %s != %s", item.Type, SecretItemType)
	}
	return Bytes32(item.SecretData()), nil
}

// NewCertificateKeyItem creates an Item for a certificate private key.
// The publicKey is a PEM encoded X.509v3 certificate.
// The privateKey is a PEM encoded EC private key ASN.1, DER format.
func NewCertificateKeyItem(id string, privateKey string, publicKey string) *keyring.Item {
	item := keyring.NewItem(id, keyring.NewStringSecret(privateKey), string(CertificateItemType))
	item.SetSecretFor("public", keyring.NewStringSecret(publicKey))
	return item
}

// AsCertificateKey returns CertificateKey for keyring Item.
func AsCertificateKey(item *keyring.Item) (*CertificateKey, error) {
	if item.Type != string(CertificateItemType) {
		return nil, errors.Errorf("item type %s != %s", item.Type, CertificateItemType)
	}
	private := string(item.SecretData())
	public := string(item.SecretDataFor("public"))
	return NewCertificateKey(private, public)
}

// NewPassphraseItem creates keyring item for a passphrase.
func NewPassphraseItem(id string, passphrase string) *keyring.Item {
	return keyring.NewItem(id, keyring.NewStringSecret(passphrase), string(PassphraseItemType))
}

// AsPassphrase returns passphrase for keyring Item.
func AsPassphrase(item *keyring.Item) (string, error) {
	if item.Type != string(PassphraseItemType) {
		return "", errors.Errorf("item type %s != %s", item.Type, PassphraseItemType)
	}
	return string(item.SecretData()), nil
}
