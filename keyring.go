package keys

import (
	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

const (
	certificateItemType string = "cert-key-x509v3"
	passphraseItemType  string = "passphrase"
	secretItemType      string = "secret"
)

// NewBoxKeyItem creates keyring item for BoxKey.
func NewBoxKeyItem(key *BoxKey) *keyring.Item {
	return keyring.NewItem(key.ID().String(), keyring.NewSecret(key.PrivateKey()[:]), string(Curve25519))
}

// AsBoxKey returns BoxKey for keyring Item.
// If item is SignKey returns converted to BoxKey.
func AsBoxKey(item *keyring.Item) (*BoxKey, error) {
	switch item.Type {
	case string(Curve25519):
		bk := NewCurve25519KeyFromPrivateKey(Bytes32(item.SecretData()))
		return bk, nil
	case string(Ed25519):
		sk, err := AsSignKey(item)
		if err != nil {
			return nil, err
		}
		return sk.Curve25519Key(), nil
	default:
		return nil, errors.Errorf("item type %s != %s", item.Type, string(Curve25519))
	}
}

// AsBoxPublicKey returns BoxPublicKey for keyring Item.
func AsBoxPublicKey(item *keyring.Item) (*BoxPublicKey, error) {
	switch item.Type {
	case string(Curve25519Public):
		return NewCurve25519PublicKey(Bytes32(item.SecretData())), nil
	case string(Curve25519):
		bk, err := AsBoxKey(item)
		if err != nil {
			return nil, err
		}
		return bk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for sign public key: %s", item.Type)
	}
}

// NewSignKeyItem creates keyring item for SignKey.
func NewSignKeyItem(signKey *SignKey) *keyring.Item {
	return keyring.NewItem(signKey.ID().String(), keyring.NewSecret(signKey.PrivateKey()[:]), string(Ed25519))
}

// AsSignKey returns SignKey for keyring Item.
func AsSignKey(item *keyring.Item) (*SignKey, error) {
	if item.Type != string(Ed25519) {
		return nil, errors.Errorf("item type %s != %s", item.Type, string(Ed25519))
	}
	b := item.SecretData()
	if len(b) != 64 {
		return nil, errors.Errorf("invalid number of bytes for ed25519 private key")
	}
	sk := NewEd25519KeyFromPrivateKey(Bytes64(b))
	return sk, nil
}

// NewSignPublicKeyItem creates keyring item for SignPublicKey.
func NewSignPublicKeyItem(publicKey *SignPublicKey) *keyring.Item {
	return keyring.NewItem(publicKey.ID().String(), keyring.NewSecret(publicKey.Bytes()[:]), string(Ed25519Public))
}

// AsSignPublicKey returns SignPublicKey for keyring Item.
func AsSignPublicKey(item *keyring.Item) (*SignPublicKey, error) {
	switch item.Type {
	case string(Ed25519Public):
		b := item.SecretData()
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for ed25519 public key")
		}
		return NewEd25519PublicKey(Bytes32(b)), nil
	case string(Ed25519):
		sk, err := AsSignKey(item)
		if err != nil {
			return nil, err
		}
		return sk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for sign public key: %s", item.Type)
	}
}

// NewBoxPublicKeyItem creates keyring item for Curve25519PublicKey.
func NewBoxPublicKeyItem(publicKey *Curve25519PublicKey) *keyring.Item {
	return keyring.NewItem(publicKey.ID().String(), keyring.NewSecret(publicKey.Bytes()[:]), string(Curve25519Public))
}

// AsCurve25519PublicKey returns Curve25519PublicKey for keyring Item.
func AsCurve25519PublicKey(item *keyring.Item) (*Curve25519PublicKey, error) {
	switch item.Type {
	case string(Curve25519Public):
		b := item.SecretData()
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for curve25519 public key")
		}
		return NewCurve25519PublicKey(Bytes32(b)), nil
	case string(Curve25519):
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
	return keyring.NewItem(kid, keyring.NewSecret(secretKey[:]), secretItemType)
}

// AsSecretKey returns SecretKey for keyring Item.
func AsSecretKey(item *keyring.Item) (SecretKey, error) {
	if item.Type != secretItemType {
		return nil, errors.Errorf("item type %s != %s", item.Type, secretItemType)
	}
	b := item.SecretData()
	if len(b) != 32 {
		return nil, errors.Errorf("invalid number of bytes for secret key")
	}
	return Bytes32(b), nil
}

// NewCertificateKeyItem creates an Item for a certificate private key.
// The publicKey is a PEM encoded X.509v3 certificate.
// The privateKey is a PEM encoded EC private key ASN.1, DER format.
func NewCertificateKeyItem(id string, privateKey string, publicKey string) *keyring.Item {
	item := keyring.NewItem(id, keyring.NewStringSecret(privateKey), certificateItemType)
	item.SetSecretFor("public", keyring.NewStringSecret(publicKey))
	return item
}

// AsCertificateKey returns CertificateKey for keyring Item.
func AsCertificateKey(item *keyring.Item) (*CertificateKey, error) {
	if item.Type != certificateItemType {
		return nil, errors.Errorf("item type %s != %s", item.Type, certificateItemType)
	}
	private := string(item.SecretData())
	public := string(item.SecretDataFor("public"))
	return NewCertificateKey(private, public)
}

// NewPassphraseItem creates keyring item for a passphrase.
func NewPassphraseItem(id string, passphrase string) *keyring.Item {
	return keyring.NewItem(id, keyring.NewStringSecret(passphrase), passphraseItemType)
}

// AsPassphrase returns passphrase for keyring Item.
func AsPassphrase(item *keyring.Item) (string, error) {
	if item.Type != passphraseItemType {
		return "", errors.Errorf("item type %s != %s", item.Type, passphraseItemType)
	}
	return string(item.SecretData()), nil
}
