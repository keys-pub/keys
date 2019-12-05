package saltpack

import (
	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/sign"
)

// SignKey is a wrapper for
type SignKey struct {
	ksaltpack.SigningSecretKey
	privateKey keys.SignPrivateKey
	publicKey  keys.SignPublicKey
}

// NewSignKey creates SigningSecretKey from a keys.SignKey.
func NewSignKey(sk *keys.SignKey) *SignKey {
	return &SignKey{
		privateKey: sk.PrivateKey(),
		publicKey:  sk.PublicKey,
	}
}

// Sign (for ksaltpack.SigningSecretKey)
func (k *SignKey) Sign(message []byte) ([]byte, error) {
	signedMessage := sign.Sign(nil, message, k.privateKey)
	return signedMessage[:sign.Overhead], nil
}

// GetPublicKey (for ksaltpack.SigningSecretKey)
func (k *SignKey) GetPublicKey() ksaltpack.SigningPublicKey {
	return NewSignPublicKey(k.publicKey)
}

// SignPublicKey is a wrapper for keys.SignPublicKey.
type SignPublicKey struct {
	ksaltpack.SigningPublicKey
	pk keys.SignPublicKey
}

// NewSignPublicKey creates SignPublicKey for keys.SignPublicKey.
func NewSignPublicKey(pk keys.SignPublicKey) *SignPublicKey {
	return &SignPublicKey{pk: pk}
}

// ToKID (for ksaltpack.SigningPublicKey)
func (k SignPublicKey) ToKID() []byte {
	return k.pk[:]
}

// Verify (for ksaltpack.SigningPublicKey)
func (k SignPublicKey) Verify(message []byte, signature []byte) error {
	signedMessage := append(signature, message...)
	_, ok := sign.Open(nil, signedMessage, k.pk)
	if !ok {
		return errors.Errorf("failed to verify")
	}
	return nil
}
