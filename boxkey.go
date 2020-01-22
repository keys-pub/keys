package keys

import (
	"bytes"

	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// BoxPrivateKeySize is the size for private key bytes
const BoxPrivateKeySize = 32

// BoxPublicKeySize is the size for public key bytes
const BoxPublicKeySize = 32

// BoxPublicKey is the public key part of a box key.
type BoxPublicKey struct {
	id        ID
	publicKey *[BoxPublicKeySize]byte
}

// BoxKeyType (Curve25519).
const BoxKeyType KeyType = "kpc"

// BoxKey is a Curve25519 assymmetric encryption key.
type BoxKey struct {
	id         ID
	publicKey  *BoxPublicKey
	privateKey *[BoxPrivateKeySize]byte
}

// ID is key identifer.
func (k BoxKey) ID() ID {
	return k.id
}

// PrivateKey returns private part of this BoxKey.
func (k BoxKey) PrivateKey() *[BoxPrivateKeySize]byte {
	return k.privateKey
}

// PublicKey returns public part of this BoxKey.
func (k BoxKey) PublicKey() *BoxPublicKey {
	return k.publicKey
}

// GenerateBoxKey creates a new BoxKey.
func GenerateBoxKey() *BoxKey {
	return NewBoxKeyFromSeed(Rand32())
}

// boxPublicKeyFromID converts ID to BoxPublicKey.
func boxPublicKeyFromID(id ID) (*BoxPublicKey, error) {
	hrp, b, err := id.Decode()
	if err != nil {
		return nil, err
	}
	if hrp != string(BoxKeyType) {
		return nil, errors.Errorf("invalid key type")
	}
	if len(b) != BoxPublicKeySize {
		return nil, errors.Errorf("invalid box public key bytes")
	}
	return NewBoxPublicKey(Bytes32(b)), nil
}

// NewBoxKeyFromSeed from seed.
func NewBoxKeyFromSeed(seed *[32]byte) *BoxKey {
	publicKey, privateKey, err := box.GenerateKey(bytes.NewReader(seed[:]))
	if err != nil {
		panic(err)
	}
	return &BoxKey{
		id:         MustID(string(BoxKeyType), publicKey[:]),
		publicKey:  NewBoxPublicKey(publicKey),
		privateKey: privateKey,
	}
}

// NewBoxKeyFromPrivateKey creates a BoxKey from private key bytes.
func NewBoxKeyFromPrivateKey(privateKey *[BoxPrivateKeySize]byte) *BoxKey {
	publicKey := new([32]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return &BoxKey{
		id:         MustID(string(BoxKeyType), publicKey[:]),
		privateKey: privateKey,
		publicKey:  NewBoxPublicKey(publicKey),
	}
}

// Seal encrypts message with nacl.box Seal.
func (k *BoxKey) Seal(b []byte, nonce *[24]byte, recipient *BoxPublicKey) []byte {
	return box.Seal(nil, b, nonce, recipient.Bytes(), k.privateKey)
}

// Open decrypts message with nacl.box Open.
func (k *BoxKey) Open(b []byte, nonce *[24]byte, sender *BoxPublicKey) ([]byte, bool) {
	return box.Open(nil, b, nonce, sender.Bytes(), k.privateKey)
}

// NewBoxPublicKey creates BoxPublicKey.
func NewBoxPublicKey(b *[BoxPublicKeySize]byte) *BoxPublicKey {
	id, err := NewID(string(BoxKeyType), b[:])
	if err != nil {
		panic(err)
	}
	return &BoxPublicKey{
		id:        id,
		publicKey: b,
	}
}

// ID for box public key.
func (k BoxPublicKey) ID() ID {
	return k.id
}

// Bytes for box public key.
func (k BoxPublicKey) Bytes() *[BoxPublicKeySize]byte {
	return k.publicKey
}
