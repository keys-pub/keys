package keys

import (
	"github.com/keys-pub/keys/keyring"
)

// NewSecretKeyItem creates keyring item for SecretKey.
func NewSecretKeyItem(kid ID, secretKey SecretKey) *keyring.Item {
	return keyring.NewItem(kid.String(), keyring.NewSecret(secretKey[:]), SecretKeyType)
}

// NewBoxKeyItem creates keyring item for BoxKey.
func NewBoxKeyItem(boxKey *BoxKey) *keyring.Item {
	return keyring.NewItem(boxKey.ID.String(), keyring.NewSecret(boxKey.PrivateKey()[:]), BoxKeyType)
}

// NewSignKeyItem creates keyring item for SignKey.
func NewSignKeyItem(signKey *SignKey) *keyring.Item {
	return keyring.NewItem(signKey.ID.String(), keyring.NewSecret(signKey.PrivateKey()[:]), SignKeyType)
}

// NewSignPublicKeyItem creates keyring item for SignPublicKey.
func NewSignPublicKeyItem(publicKey SignPublicKey) *keyring.Item {
	id, err := NewID(publicKey[:])
	if err != nil {
		panic(err)
	}
	return keyring.NewItem(id.String(), keyring.NewSecret(publicKey[:]), SignPublicKeyType)
}

// NewBoxPublicKeyItem creates keyring item for BoxPublicKey.
func NewBoxPublicKeyItem(publicKey BoxPublicKey) *keyring.Item {
	id, err := NewID(publicKey[:])
	if err != nil {
		panic(err)
	}
	return keyring.NewItem(id.String(), keyring.NewSecret(publicKey[:]), BoxPublicKeyType)
}

// NewPassphraseItem creates keyring item for a passphrase.
func NewPassphraseItem(id string, passphrase string) *keyring.Item {
	return keyring.NewItem(id, keyring.NewStringSecret(passphrase), PassphraseType)
}

// NewCertificateKeyItem creates an Item for a certificate private key.
// The publicKey is a PEM encoded X.509v3 certificate.
// The privateKey is a PEM encoded EC private key ASN.1, DER format.
func NewCertificateKeyItem(id string, privateKey string, publicKey string) *keyring.Item {
	item := keyring.NewItem(id, keyring.NewStringSecret(privateKey), CertificateKeyType)
	item.SetSecretFor("public", keyring.NewStringSecret(publicKey))
	return item
}

// newCertificatePublicItem creates an Item for a PEM encoded X.509v3 certificate.
// To create an Item for a certificate private key, use NewCertificateKeyItem.
// func newCertificatePublicItem(id string, public string) *keyring.Item {
// 	return keyring.NewItem(id, []byte(public), CertificatePublicKeyType)
// }

// NewKeyItem creates keyring item for Key.
func NewKeyItem(key Key) *keyring.Item {
	return keyring.NewItem(key.ID().String(), keyring.NewSecret(key.Seed()[:]), KeyType)
}
