package keys

import (
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/sign"
)

// EdX25519PublicKey is the public part of EdX25519 key pair.
type EdX25519PublicKey struct {
	id        ID
	publicKey *[ed25519.PublicKeySize]byte
	metadata  *Metadata
}

// EdX25519 key.
const EdX25519 KeyType = "edx25519"
const edx25519KeyHRP string = "kex"

// EdX25519Public public key.
const EdX25519Public KeyType = "ed25519-public"

// EdX25519Key is a EdX25519 key capable of signing and encryption (converted to a X25519 key).
type EdX25519Key struct {
	privateKey *[ed25519.PrivateKeySize]byte
	publicKey  *EdX25519PublicKey
}

// NewEdX25519KeyFromPrivateKey constructs EdX25519Key from a private key.
// The public key is derived from the private key.
func NewEdX25519KeyFromPrivateKey(privateKey *[ed25519.PrivateKeySize]byte) *EdX25519Key {
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

	return &EdX25519Key{
		privateKey: &privateKeyBytes,
		publicKey:  NewEdX25519PublicKey(&publicKeyBytes),
	}
}

// X25519Key converts EdX25519Key to X25519Key.
func (k *EdX25519Key) X25519Key() *X25519Key {
	secretKey := ed25519PrivateKeyToCurve25519(ed25519.PrivateKey(k.privateKey[:]))
	if len(secretKey) != 32 {
		panic("failed to convert key: invalid secret key bytes")
	}
	return NewX25519KeyFromPrivateKey(Bytes32(secretKey))
}

// ID ...
func (k EdX25519Key) ID() ID {
	return k.publicKey.ID()
}

// Type ...
func (k EdX25519Key) Type() KeyType {
	return EdX25519
}

// Bytes for key.
func (k EdX25519Key) Bytes() []byte {
	return k.privateKey[:]
}

// Metadata for key.
func (k EdX25519Key) Metadata() *Metadata {
	return k.publicKey.metadata
}

// Bytes64 for key.
func (k EdX25519Key) Bytes64() *[64]byte {
	return k.privateKey
}

// NewEdX25519PublicKey creates a EdX25519PublicKey.
// Metadata is optional.
func NewEdX25519PublicKey(b *[ed25519.PublicKeySize]byte) *EdX25519PublicKey {
	return &EdX25519PublicKey{
		id:        MustID(edx25519KeyHRP, b[:]),
		publicKey: b,
		metadata:  &Metadata{},
	}
}

// NewEdX25519PublicKeyFromID converts ID to EdX25519PublicKey.
func NewEdX25519PublicKeyFromID(id ID) (*EdX25519PublicKey, error) {
	if id == "" {
		return nil, errors.Errorf("empty id")
	}
	hrp, b, err := id.Decode()
	if err != nil {
		return nil, err
	}
	if hrp != edx25519KeyHRP {
		return nil, errors.Errorf("invalid key type for edx25519")
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.Errorf("invalid ed25519 public key bytes")
	}
	return &EdX25519PublicKey{
		id:        id,
		publicKey: Bytes32(b),
	}, nil
}

// PublicKeyIDEquals returns true if public keys are equal.
// It will also compare EdX25519 public key and X25519 public keys.
func PublicKeyIDEquals(expected ID, kid ID) bool {
	if expected == kid {
		return true
	}
	if expected.IsEdX25519() && kid.IsX25519() {
		spk, err := NewEdX25519PublicKeyFromID(expected)
		if err != nil {
			panic(err)
		}
		return kid == spk.X25519PublicKey().ID()
	}
	if kid.IsEdX25519() && expected.IsX25519() {
		spk, err := NewEdX25519PublicKeyFromID(kid)
		if err != nil {
			panic(err)
		}
		return expected == spk.X25519PublicKey().ID()
	}
	return false
}

// NewX25519PublicKeyFromEdX25519ID creates public key from EdX25519 key ID.
func NewX25519PublicKeyFromEdX25519ID(id ID) (*X25519PublicKey, error) {
	spk, err := NewEdX25519PublicKeyFromID(id)
	if err != nil {
		return nil, err
	}
	return spk.X25519PublicKey(), nil
}

// ID for sign public key.
func (s EdX25519PublicKey) ID() ID {
	return s.id
}

func (s EdX25519PublicKey) String() string {
	return s.id.String()
}

// Type ...
func (s *EdX25519PublicKey) Type() KeyType {
	return EdX25519Public
}

// Bytes for key.
func (s EdX25519PublicKey) Bytes() []byte {
	return s.publicKey[:]
}

// Bytes32 for key.
func (s EdX25519PublicKey) Bytes32() *[32]byte {
	return s.publicKey
}

// Metadata for key.
func (s EdX25519PublicKey) Metadata() *Metadata {
	return s.metadata
}

// X25519PublicKey converts the ed25519 public key to a x25519 public key.
func (s EdX25519PublicKey) X25519PublicKey() *X25519PublicKey {
	edpk := ed25519.PublicKey(s.publicKey[:])
	bpk := ed25519PublicKeyToCurve25519(edpk)
	if len(bpk) != 32 {
		panic("unable to convert key: invalid public key bytes")
	}
	key := NewX25519PublicKey(Bytes32(bpk))
	// TODO: Copy metadata?
	// key.metadata = s.metadata
	return key
}

// Verify verifies a message and signature with public key.
func (s EdX25519PublicKey) Verify(b []byte) ([]byte, error) {
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
func (s EdX25519PublicKey) VerifyDetached(sig []byte, b []byte) error {
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

// NewEdX25519KeyFromSeed constructs EdX25519Key from an ed25519 seed.
// The private key is derived from this seed and the public key is derived from the private key.
func NewEdX25519KeyFromSeed(seed *[ed25519.SeedSize]byte) *EdX25519Key {
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return NewEdX25519KeyFromPrivateKey(Bytes64(privateKey))
}

// Seed returns information on how to generate this key from ed25519 package seed.
func (k EdX25519Key) Seed() *[ed25519.SeedSize]byte {
	pk := ed25519.PrivateKey(k.privateKey[:])
	return Bytes32(pk.Seed())
}

func (k EdX25519Key) String() string {
	return k.publicKey.String()
}

// PublicKey returns public part.
func (k EdX25519Key) PublicKey() *EdX25519PublicKey {
	return k.publicKey
}

// PrivateKey returns private key part.
func (k EdX25519Key) PrivateKey() *[ed25519.PrivateKeySize]byte {
	return k.privateKey
}

// Sign bytes with the (sign) private key.
func (k *EdX25519Key) Sign(b []byte) []byte {
	return Sign(b, k)
}

// SignDetached sign bytes detached.
func (k *EdX25519Key) SignDetached(b []byte) []byte {
	return SignDetached(b, k)
}

// Sign bytes.
func Sign(b []byte, sk *EdX25519Key) []byte {
	return sign.Sign(nil, b, sk.privateKey)
}

// SignDetached sign bytes detached.
func SignDetached(b []byte, sk *EdX25519Key) []byte {
	return Sign(b, sk)[:sign.Overhead]
}

// GenerateEdX25519Key generates a EdX25519Key (EdX25519).
func GenerateEdX25519Key() *EdX25519Key {
	logger.Infof("Generating EdX25519 key...")
	seed := Rand32()
	key := NewEdX25519KeyFromSeed(seed)
	key.Metadata().CreatedAt = time.Now()
	// key.Metadata().UpdatedAt = time.Now()
	return key
}
