package keys

import (
	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

const (
	// SecretKeyringType ...
	SecretKeyringType string = "secret-key"
	// CertificateKeyringType ...
	CertificateKeyringType string = "cert-key"
	// CertificatePublicKeyringType ...
	CertificatePublicKeyringType string = "cert-public-key"
	// PassphraseKeyringType ...
	PassphraseKeyringType string = "passphrase"
	// BoxKeyringType ...
	BoxKeyringType string = "box-key"
	// BoxPublicKeyringType ...
	BoxPublicKeyringType string = "box-public-key"
	// SignKeyringType ...
	SignKeyringType string = "sign-key"
	// SignPublicKeyringType ...
	SignPublicKeyringType string = "sign-public-key"
)

// NewSecretKeyItem creates keyring item for SecretKey.
func NewSecretKeyItem(kid string, secretKey SecretKey) *keyring.Item {
	return keyring.NewItem(kid, keyring.NewSecret(secretKey[:]), SecretKeyringType)
}

// AsSecretKey returns SecretKey for keyring Item.
func AsSecretKey(item *keyring.Item) (SecretKey, error) {
	if item.Type != SecretKeyringType {
		return nil, errors.Errorf("item type %s != %s", item.Type, SecretKeyringType)
	}
	return Bytes32(item.SecretData()), nil
}

// NewBoxKeyItem creates keyring item for BoxKey.
func NewBoxKeyItem(boxKey *BoxKey) *keyring.Item {
	return keyring.NewItem(boxKey.ID().String(), keyring.NewSecret(boxKey.PrivateKey()[:]), BoxKeyringType)
}

// AsBoxKey returns BoxKey for keyring Item.
func AsBoxKey(item *keyring.Item) (*BoxKey, error) {
	if item.Type != BoxKeyringType {
		return nil, errors.Errorf("item type %s != %s", item.Type, BoxKeyringType)
	}
	boxKey := NewBoxKeyFromPrivateKey(Bytes32(item.SecretData()))
	return boxKey, nil
}

// NewSignKeyItem creates keyring item for SignKey.
func NewSignKeyItem(signKey *SignKey) *keyring.Item {
	return keyring.NewItem(signKey.ID().String(), keyring.NewSecret(signKey.PrivateKey()[:]), SignKeyringType)
}

// AsSignKey returns SignKey for keyring Item.
func AsSignKey(item *keyring.Item) (*SignKey, error) {
	if item.Type != SignKeyringType {
		return nil, errors.Errorf("item type %s != %s", item.Type, SignKeyringType)
	}
	sk, err := NewSignKeyFromPrivateKey(item.SecretData())
	if err != nil {
		return nil, err
	}
	return sk, nil
}

// NewSignPublicKeyItem creates keyring item for SignPublicKey.
func NewSignPublicKeyItem(publicKey *SignPublicKey) *keyring.Item {
	return keyring.NewItem(publicKey.ID().String(), keyring.NewSecret(publicKey.Bytes()[:]), SignPublicKeyringType)
}

// AsSignPublicKey returns SignPublicKey for keyring Item.
func AsSignPublicKey(item *keyring.Item) (*SignPublicKey, error) {
	switch item.Type {
	case SignPublicKeyringType:
		return NewSignPublicKey(Bytes32(item.SecretData())), nil
	case SignKeyringType:
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
func NewBoxPublicKeyItem(publicKey BoxPublicKey) *keyring.Item {
	id, err := NewID(SignKeyType, publicKey[:])
	if err != nil {
		panic(err)
	}
	return keyring.NewItem(id.String(), keyring.NewSecret(publicKey[:]), BoxPublicKeyringType)
}

// NewPassphraseItem creates keyring item for a passphrase.
func NewPassphraseItem(id string, passphrase string) *keyring.Item {
	return keyring.NewItem(id, keyring.NewStringSecret(passphrase), PassphraseKeyringType)
}

// AsPassphrase returns passphrase for keyring Item.
func AsPassphrase(item *keyring.Item) (string, error) {
	if item.Type != PassphraseKeyringType {
		return "", errors.Errorf("item type %s != %s", item.Type, PassphraseKeyringType)
	}
	return string(item.SecretData()), nil
}

// NewCertificateKeyItem creates an Item for a certificate private key.
// The publicKey is a PEM encoded X.509v3 certificate.
// The privateKey is a PEM encoded EC private key ASN.1, DER format.
func NewCertificateKeyItem(id string, privateKey string, publicKey string) *keyring.Item {
	item := keyring.NewItem(id, keyring.NewStringSecret(privateKey), CertificateKeyringType)
	item.SetSecretFor("public", keyring.NewStringSecret(publicKey))
	return item
}

// AsCertificateKey returns CertificateKey for keyring Item.
func AsCertificateKey(item *keyring.Item) (*CertificateKey, error) {
	if item.Type != CertificateKeyringType {
		return nil, errors.Errorf("item type %s != %s", item.Type, CertificateKeyringType)
	}
	private := string(item.SecretData())
	public := string(item.SecretDataFor("public"))
	return NewCertificateKey(private, public)
}
