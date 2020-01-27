package keys

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/sign"
)

// Ed25519PublicKey is the public part of Ed25519 key pair.
type Ed25519PublicKey struct {
	id        ID
	publicKey *[ed25519.PublicKeySize]byte
}

// Ed25519 key.
const Ed25519 KeyType = "ed25519"
const edKeyHRP string = "kse"

// Ed25519Public public key.
const Ed25519Public KeyType = "ed25519-public"

// Ed25519Key is a Ed25519 key capable of signing and encryption (converted to a Curve25519 key).
type Ed25519Key struct {
	privateKey *[ed25519.PrivateKeySize]byte
	publicKey  *Ed25519PublicKey
}

// NewEd25519KeyFromPrivateKey constructs Ed25519Key from a private key.
// The public key is derived from the private key.
func NewEd25519KeyFromPrivateKey(privateKey *[ed25519.PrivateKeySize]byte) *Ed25519Key {
	// Derive public key from private key
	edpk := ed25519.PrivateKey(privateKey[:])
	publicKey := edpk.Public().(ed25519.PublicKey)
	if len(publicKey) != ed25519.PublicKeySize {
		panic(errors.Errorf("invalid public key bytes (len=%d)", len(publicKey)))
	}

	var privateKeyBytes [ed25519.PrivateKeySize]byte
	copy(privateKeyBytes[:], privateKey[:ed25519.PrivateKeySize])

	var publicKeyBytes [ed25519.PublicKeySize]byte
	copy(publicKeyBytes[:], publicKey[:ed25519.PublicKeySize])

	return &Ed25519Key{
		privateKey: &privateKeyBytes,
		publicKey: &Ed25519PublicKey{
			id:        MustID(edKeyHRP, publicKeyBytes[:]),
			publicKey: &publicKeyBytes,
		},
	}
}

// Curve25519Key converts Ed25519Key to Curve25519Key.
func (k *Ed25519Key) Curve25519Key() *Curve25519Key {
	secretKey := ed25519PrivateKeyToCurve25519(ed25519.PrivateKey(k.privateKey[:]))
	if len(secretKey) != 32 {
		panic("failed to convert key: invalid secret key bytes")
	}
	return NewCurve25519KeyFromPrivateKey(Bytes32(secretKey))
}

// ID ...
func (k Ed25519Key) ID() ID {
	return k.publicKey.ID()
}

// Type ...
func (k Ed25519Key) Type() KeyType {
	return Ed25519
}

// Bytes for key.
func (k Ed25519Key) Bytes() []byte {
	return k.privateKey[:]
}

// Bytes64 for key.
func (k Ed25519Key) Bytes64() *[64]byte {
	return k.privateKey
}

// NewEd25519PublicKey creates a Ed25519PublicKey.
func NewEd25519PublicKey(b *[ed25519.PublicKeySize]byte) *Ed25519PublicKey {
	return &Ed25519PublicKey{
		id:        MustID(edKeyHRP, b[:]),
		publicKey: b,
	}
}

// Ed25519PublicKeyFromID converts ID to Ed25519PublicKey.
func Ed25519PublicKeyFromID(id ID) (*Ed25519PublicKey, error) {
	hrp, b, err := id.Decode()
	if err != nil {
		return nil, err
	}
	if hrp != edKeyHRP {
		return nil, errors.Errorf("invalid key type")
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.Errorf("invalid ed25519 public key bytes")
	}
	return &Ed25519PublicKey{
		id:        id,
		publicKey: Bytes32(b),
	}, nil
}

// ID for sign public key.
func (s Ed25519PublicKey) ID() ID {
	return s.id
}

func (s Ed25519PublicKey) String() string {
	return s.id.String()
}

// Type ...
func (s *Ed25519PublicKey) Type() KeyType {
	return Ed25519Public
}

// Bytes for key.
func (s Ed25519PublicKey) Bytes() []byte {
	return s.publicKey[:]
}

// Bytes32 for key.
func (s Ed25519PublicKey) Bytes32() *[32]byte {
	return s.publicKey
}

// Curve25519PublicKey converts the ed25519 public key to a curve25519 public key.
func (s Ed25519PublicKey) Curve25519PublicKey() *Curve25519PublicKey {
	edpk := ed25519.PublicKey(s.publicKey[:])
	bpk := ed25519PublicKeyToCurve25519(edpk)
	if len(bpk) != 32 {
		panic("unable to convert key: invalid public key bytes")
	}
	return NewCurve25519PublicKey(Bytes32(bpk))
}

// Verify verifies a message and signature with public key.
func (s Ed25519PublicKey) Verify(b []byte) ([]byte, error) {
	if l := len(b); l < sign.Overhead {
		return nil, errors.Errorf("not enough data for signature")
	}
	_, ok := sign.Open(nil, b, s.publicKey)
	if !ok {
		return nil, errors.Errorf("verify failed")
	}
	return b[sign.Overhead:], nil
}

// VerifyDetached verifies a detached message.
func (s Ed25519PublicKey) VerifyDetached(sig []byte, b []byte) error {
	if len(sig) != sign.Overhead {
		return errors.Errorf("invalid sig bytes length")
	}
	if len(b) == 0 {
		return errors.Errorf("no bytes")
	}
	msg := bytesJoin(sig, b)
	_, err := s.Verify(msg)
	return err
}

// NewEd25519KeyFromSeed constructs Ed25519Key from an ed25519 seed.
// The private key is derived from this seed and the public key is derived from the private key.
func NewEd25519KeyFromSeed(seed *[ed25519.SeedSize]byte) *Ed25519Key {
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return NewEd25519KeyFromPrivateKey(Bytes64(privateKey))
}

// Seed returns information on how to generate this key from ed25519 package seed.
func (k Ed25519Key) Seed() *[ed25519.SeedSize]byte {
	pk := ed25519.PrivateKey(k.privateKey[:])
	return Bytes32(pk.Seed())
}

func (k Ed25519Key) String() string {
	return k.publicKey.String()
}

// PublicKey returns public part.
func (k Ed25519Key) PublicKey() *Ed25519PublicKey {
	return k.publicKey
}

// PrivateKey returns private key part.
func (k Ed25519Key) PrivateKey() *[ed25519.PrivateKeySize]byte {
	return k.privateKey
}

// Sign bytes with the (sign) private key.
func (k *Ed25519Key) Sign(b []byte) []byte {
	return Sign(b, k)
}

// SignDetached sign bytes detached.
func (k *Ed25519Key) SignDetached(b []byte) []byte {
	return SignDetached(b, k)
}

// Sign bytes.
func Sign(b []byte, sk *Ed25519Key) []byte {
	return sign.Sign(nil, b, sk.privateKey)
}

// SignDetached sign bytes detached.
func SignDetached(b []byte, sk *Ed25519Key) []byte {
	return Sign(b, sk)[:sign.Overhead]
}

// GenerateEd25519Key generates a Ed25519Key (Ed25519).
func GenerateEd25519Key() *Ed25519Key {
	logger.Infof("Generating ed25519 key...")
	seed := Rand32()
	return NewEd25519KeyFromSeed(seed)
}
