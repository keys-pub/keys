package keys

import (
	"crypto/rand"

	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// BoxPrivateKeySize is the size for private key bytes
const BoxPrivateKeySize = 32

// BoxPublicKeySize is the size for public key bytes
const BoxPublicKeySize = 32

// BoxPrivateKey is the private key part of a nacl.box compatible key
type BoxPrivateKey *[BoxPrivateKeySize]byte

// BoxPublicKey is the public key part of a nacl.box compatible key
type BoxPublicKey *[BoxPublicKeySize]byte

// BoxKey is a nacl.box compatible public/private key
type BoxKey struct {
	PublicKey  BoxPublicKey
	privateKey BoxPrivateKey
	ID
}

// PrivateKey returns private key part of this BoxKey
func (k BoxKey) PrivateKey() BoxPrivateKey {
	return k.privateKey
}

// GenerateBoxKey creates a new BoxKey
func GenerateBoxKey() *BoxKey {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &BoxKey{
		PublicKey:  publicKey,
		privateKey: privateKey,
		ID:         MustID(publicKey[:]),
	}
}

// NewBoxKeyFromPrivateKey creates a BoxKey from private key bytes.
func NewBoxKeyFromPrivateKey(privateKey *[32]byte) *BoxKey {
	publicKey := new([32]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return &BoxKey{
		privateKey: privateKey,
		PublicKey:  publicKey,
		ID:         MustID(publicKey[:]),
	}
}

// Seal encrypts message with nacl.box Seal.
func (k *BoxKey) Seal(b []byte, nonce *[24]byte, recipient BoxPublicKey) []byte {
	return box.Seal(nil, b, nonce, recipient, k.privateKey)
}

// Open decrypts message with nacl.box Open.
func (k *BoxKey) Open(b []byte, nonce *[24]byte, sender BoxPublicKey) ([]byte, bool) {
	return box.Open(nil, b, nonce, sender, k.privateKey)
}

// BoxPublicKeyID returns ID for BoxPublicKey.
func BoxPublicKeyID(bpk BoxPublicKey) ID {
	return MustID(bpk[:])
}

// DecodeBoxPublicKey returns BoxPublicKey from a string.
func DecodeBoxPublicKey(s string) (BoxPublicKey, error) {
	b, err := Decode(s, Base58)
	if err != nil {
		return nil, err
	}
	if len(b) != BoxPublicKeySize {
		return nil, errors.Errorf("invalid box public key bytes")
	}
	return Bytes32(b), nil
}
