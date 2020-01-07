package saltpack

import (
	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"golang.org/x/crypto/nacl/sign"
)

// signKey is a wrapper for keys.SignKey.
type signKey struct {
	ksaltpack.SigningSecretKey
	privateKey keys.SignPrivateKey
	publicKey  *keys.SignPublicKey
}

// newSignKey creates SigningSecretKey from a keys.SignKey.
func newSignKey(sk *keys.SignKey) *signKey {
	return &signKey{
		privateKey: sk.PrivateKey(),
		publicKey:  sk.PublicKey(),
	}
}

func (k *signKey) Sign(message []byte) ([]byte, error) {
	signedMessage := sign.Sign(nil, message, k.privateKey)
	return signedMessage[:sign.Overhead], nil
}

func (k *signKey) GetPublicKey() ksaltpack.SigningPublicKey {
	return newSignPublicKey(k.publicKey)
}

// signPublicKey is a wrapper for keys.SignPublicKey.
type signPublicKey struct {
	ksaltpack.SigningPublicKey
	pk *keys.SignPublicKey
}

// newSignPublicKey creates SignPublicKey for keys.SignPublicKey.
func newSignPublicKey(pk *keys.SignPublicKey) *signPublicKey {
	return &signPublicKey{pk: pk}
}

func (k signPublicKey) ToKID() []byte {
	return k.pk.Bytes()[:]
}

func (k signPublicKey) Verify(message []byte, signature []byte) error {
	signedMessage := append(signature, message...)
	_, err := k.pk.Verify(signedMessage)
	return err
}
