package keys

import (
	"bytes"

	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Curve25519PublicKey is the public key part of a curve25519 key.
type Curve25519PublicKey struct {
	id        ID
	publicKey *[32]byte
}

// Curve25519 key type.
const Curve25519 KeyType = "curve25519"
const curveKeyHRP string = "kbc"

// Curve25519Public public key type.
const Curve25519Public KeyType = "curve25519-public"

// Curve25519Key is a Curve25519 assymmetric encryption key.
type Curve25519Key struct {
	id         ID
	publicKey  *Curve25519PublicKey
	privateKey *[32]byte
}

// ID is key identifer.
func (k Curve25519Key) ID() ID {
	return k.id
}

// Type of key.
func (k Curve25519Key) Type() KeyType {
	return Curve25519
}

// Bytes for key.
func (k Curve25519Key) Bytes() []byte {
	return k.privateKey[:]
}

// Bytes32 for key.
func (k Curve25519Key) Bytes32() *[32]byte {
	return k.privateKey
}

// PrivateKey returns private part of this Curve25519Key.
func (k Curve25519Key) PrivateKey() *[32]byte {
	return k.privateKey
}

// PublicKey returns public part of this Curve25519Key.
func (k Curve25519Key) PublicKey() *Curve25519PublicKey {
	return k.publicKey
}

// GenerateCurve25519Key creates a new Curve25519Key.
func GenerateCurve25519Key() *Curve25519Key {
	return NewCurve25519KeyFromSeed(Rand32())
}

// Curve25519PublicKeyFromID converts ID to Curve25519PublicKey.
func Curve25519PublicKeyFromID(id ID) (*Curve25519PublicKey, error) {
	hrp, b, err := id.Decode()
	if err != nil {
		return nil, err
	}
	if hrp != curveKeyHRP {
		return nil, errors.Errorf("invalid key type")
	}
	if len(b) != 32 {
		return nil, errors.Errorf("invalid box public key bytes")
	}
	return NewCurve25519PublicKey(Bytes32(b)), nil
}

// NewCurve25519KeyFromSeed from seed.
func NewCurve25519KeyFromSeed(seed *[32]byte) *Curve25519Key {
	publicKey, privateKey, err := box.GenerateKey(bytes.NewReader(seed[:]))
	if err != nil {
		panic(err)
	}
	return &Curve25519Key{
		id:         MustID(curveKeyHRP, publicKey[:]),
		publicKey:  NewCurve25519PublicKey(publicKey),
		privateKey: privateKey,
	}
}

// NewCurve25519KeyFromPrivateKey creates a Curve25519Key from private key bytes.
func NewCurve25519KeyFromPrivateKey(privateKey *[32]byte) *Curve25519Key {
	publicKey := new([32]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return &Curve25519Key{
		id:         MustID(curveKeyHRP, publicKey[:]),
		privateKey: privateKey,
		publicKey:  NewCurve25519PublicKey(publicKey),
	}
}

// Seal encrypts message with nacl.box Seal.
func (k *Curve25519Key) Seal(b []byte, nonce *[24]byte, recipient *Curve25519PublicKey) []byte {
	return box.Seal(nil, b, nonce, recipient.Bytes32(), k.privateKey)
}

// Open decrypts message with nacl.box Open.
func (k *Curve25519Key) Open(b []byte, nonce *[24]byte, sender *Curve25519PublicKey) ([]byte, bool) {
	return box.Open(nil, b, nonce, sender.Bytes32(), k.privateKey)
}

// NewCurve25519PublicKey creates Curve25519PublicKey.
func NewCurve25519PublicKey(b *[32]byte) *Curve25519PublicKey {
	id, err := NewID(curveKeyHRP, b[:])
	if err != nil {
		panic(err)
	}
	return &Curve25519PublicKey{
		id:        id,
		publicKey: b,
	}
}

// ID for box public key.
func (k Curve25519PublicKey) ID() ID {
	return k.id
}

// Type of key.
func (k Curve25519PublicKey) Type() KeyType {
	return Curve25519Public
}

// Bytes for key.
func (k Curve25519PublicKey) Bytes() []byte {
	return k.publicKey[:]
}

// Bytes32 for key.
func (k Curve25519PublicKey) Bytes32() *[32]byte {
	return k.publicKey
}
