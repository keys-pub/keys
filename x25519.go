package keys

import (
	"bytes"

	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// X25519PublicKey is the public key part of a x25519 key.
type X25519PublicKey struct {
	id        ID
	publicKey *[32]byte
}

// X25519 key type.
const X25519 KeyType = "x25519"
const x25519KeyHRP string = "kbx"

// X25519Public public key type.
const X25519Public KeyType = "x25519-public"

// X25519Key is a X25519 assymmetric encryption key.
type X25519Key struct {
	id         ID
	publicKey  *X25519PublicKey
	privateKey *[32]byte
}

// ID is key identifer.
func (k X25519Key) ID() ID {
	return k.id
}

// Type of key.
func (k X25519Key) Type() KeyType {
	return X25519
}

// Bytes for key.
func (k X25519Key) Bytes() []byte {
	return k.privateKey[:]
}

// Bytes32 for key.
func (k X25519Key) Bytes32() *[32]byte {
	return k.privateKey
}

// PrivateKey returns private part of this X25519Key.
func (k X25519Key) PrivateKey() *[32]byte {
	return k.privateKey
}

// PublicKey returns public part of this X25519Key.
func (k X25519Key) PublicKey() *X25519PublicKey {
	return k.publicKey
}

// GenerateX25519Key creates a new X25519Key.
func GenerateX25519Key() *X25519Key {
	logger.Infof("Generating X25519 key...")
	key := NewX25519KeyFromSeed(Rand32())
	return key
}

// NewX25519KeyFromSeed from seed.
func NewX25519KeyFromSeed(seed *[32]byte) *X25519Key {
	publicKey, privateKey, err := box.GenerateKey(bytes.NewReader(seed[:]))
	if err != nil {
		panic(err)
	}
	return &X25519Key{
		id:         MustID(x25519KeyHRP, publicKey[:]),
		publicKey:  NewX25519PublicKey(publicKey),
		privateKey: privateKey,
	}
}

// NewX25519KeyFromPrivateKey creates a X25519Key from private key bytes.
func NewX25519KeyFromPrivateKey(privateKey *[32]byte) *X25519Key {
	publicKey := new([32]byte)
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return &X25519Key{
		id:         MustID(x25519KeyHRP, publicKey[:]),
		privateKey: privateKey,
		publicKey:  NewX25519PublicKey(publicKey),
	}
}

// NewX25519PublicKeyFromID converts ID to X25519PublicKey.
func NewX25519PublicKeyFromID(id ID) (*X25519PublicKey, error) {
	if id == "" {
		return nil, errors.Errorf("empty id")
	}
	hrp, b, err := id.Decode()
	if err != nil {
		return nil, err
	}
	switch hrp {
	case x25519KeyHRP:
		if len(b) != 32 {
			return nil, errors.Errorf("invalid box public key bytes")
		}
		return NewX25519PublicKey(Bytes32(b)), nil
	case edx25519KeyHRP:
		spk, err := NewEdX25519PublicKeyFromID(id)
		if err != nil {
			return nil, err
		}
		return spk.X25519PublicKey(), nil
	default:
		return nil, errors.Errorf("unrecognized key type")
	}
}

// Seal encrypts message with nacl.box Seal.
func (k *X25519Key) Seal(b []byte, nonce *[24]byte, recipient *X25519PublicKey) []byte {
	return box.Seal(nil, b, nonce, recipient.Bytes32(), k.privateKey)
}

// Open decrypts message with nacl.box Open.
func (k *X25519Key) Open(b []byte, nonce *[24]byte, sender *X25519PublicKey) ([]byte, bool) {
	return box.Open(nil, b, nonce, sender.Bytes32(), k.privateKey)
}

// NewX25519PublicKey creates X25519PublicKey.
// Metadata is optional.
func NewX25519PublicKey(b *[32]byte) *X25519PublicKey {
	id, err := NewID(x25519KeyHRP, b[:])
	if err != nil {
		panic(err)
	}
	return &X25519PublicKey{
		id:        id,
		publicKey: b,
	}
}

// ID for box public key.
func (k X25519PublicKey) ID() ID {
	return k.id
}

// Type of key.
func (k X25519PublicKey) Type() KeyType {
	return X25519Public
}

// Bytes for key.
func (k X25519PublicKey) Bytes() []byte {
	return k.publicKey[:]
}

// Bytes32 for key.
func (k X25519PublicKey) Bytes32() *[32]byte {
	return k.publicKey
}
