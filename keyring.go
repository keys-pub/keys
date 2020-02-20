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

// NewX25519KeyItem creates keyring item for X25519Key.
func NewX25519KeyItem(key *X25519Key) *keyring.Item {
	return keyring.NewItem(key.ID().String(), keyring.NewSecret(key.PrivateKey()[:]), string(X25519))
}

// AsX25519Key returns X25519Key for keyring Item.
// If item is EdX25519Key returns converted to X25519Key.
func AsX25519Key(item *keyring.Item) (*X25519Key, error) {
	switch item.Type {
	case string(X25519):
		bk := NewX25519KeyFromPrivateKey(Bytes32(item.SecretData()))
		return bk, nil
	case string(EdX25519):
		sk, err := AsEdX25519Key(item)
		if err != nil {
			return nil, err
		}
		return sk.X25519Key(), nil
	default:
		return nil, errors.Errorf("item type %s != %s", item.Type, string(X25519))
	}
}

// NewEdX25519KeyItem creates keyring item for EdX25519Key.
func NewEdX25519KeyItem(signKey *EdX25519Key) *keyring.Item {
	return keyring.NewItem(signKey.ID().String(), keyring.NewSecret(signKey.PrivateKey()[:]), string(EdX25519))
}

// AsEdX25519Key returns EdX25519Key for keyring Item.
func AsEdX25519Key(item *keyring.Item) (*EdX25519Key, error) {
	if item.Type != string(EdX25519) {
		return nil, errors.Errorf("item type %s != %s", item.Type, string(EdX25519))
	}
	b := item.SecretData()
	if len(b) != 64 {
		return nil, errors.Errorf("invalid number of bytes for ed25519 private key")
	}
	sk := NewEdX25519KeyFromPrivateKey(Bytes64(b))
	return sk, nil
}

// NewEdX25519PublicKeyItem creates keyring item for EdX25519PublicKey.
func NewEdX25519PublicKeyItem(publicKey *EdX25519PublicKey) *keyring.Item {
	return keyring.NewItem(publicKey.ID().String(), keyring.NewSecret(publicKey.Bytes()[:]), string(EdX25519Public))
}

// AsEdX25519PublicKey returns EdX25519PublicKey for keyring Item.
func AsEdX25519PublicKey(item *keyring.Item) (*EdX25519PublicKey, error) {
	switch item.Type {
	case string(EdX25519Public):
		b := item.SecretData()
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for ed25519 public key")
		}
		return NewEdX25519PublicKey(Bytes32(b)), nil
	case string(EdX25519):
		sk, err := AsEdX25519Key(item)
		if err != nil {
			return nil, err
		}
		return sk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for sign public key: %s", item.Type)
	}
}

// NewX25519PublicKeyItem creates keyring item for X25519PublicKey.
func NewX25519PublicKeyItem(publicKey *X25519PublicKey) *keyring.Item {
	return keyring.NewItem(publicKey.ID().String(), keyring.NewSecret(publicKey.Bytes()[:]), string(X25519Public))
}

// AsX25519PublicKey returns X25519PublicKey for keyring Item.
func AsX25519PublicKey(item *keyring.Item) (*X25519PublicKey, error) {
	switch item.Type {
	case string(X25519Public):
		b := item.SecretData()
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for x25519 public key")
		}
		return NewX25519PublicKey(Bytes32(b)), nil
	case string(X25519):
		bk, err := AsX25519Key(item)
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
func NewCertificateKeyItem(id string, certKey *CertificateKey) *keyring.Item {
	item := keyring.NewItem(id, keyring.NewStringSecret(certKey.Private()), certificateItemType)
	item.SetSecretFor("public", keyring.NewStringSecret(certKey.Public()))
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
