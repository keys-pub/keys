package keys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/sign"
)

// EdX25519 key type.
const EdX25519 KeyType = "edx25519"
const edx25519KeyHRP string = "kex"

// SignOverhead alias for (nacl) sign.Overhead.
const SignOverhead = sign.Overhead

// EdX25519PublicKey is the public part of EdX25519 key pair.
type EdX25519PublicKey struct {
	id        ID
	publicKey *[ed25519.PublicKeySize]byte
}

// EdX25519Key is a EdX25519 key capable of signing and encryption (converted to a X25519 key).
type EdX25519Key struct {
	privateKey *[ed25519.PrivateKeySize]byte
	publicKey  *EdX25519PublicKey
}

// NewEdX25519KeyFromPrivateKey constructs EdX25519Key from a private key.
// The public key is derived from the private key.
func NewEdX25519KeyFromPrivateKey(privateKey *[ed25519.PrivateKeySize]byte) *EdX25519Key {
	k := &EdX25519Key{}
	if err := k.setPrivateKey(privateKey[:]); err != nil {
		panic(err)
	}
	return k
}

func (k *EdX25519Key) setPrivateKey(b []byte) error {
	if len(b) != ed25519.PrivateKeySize {
		return errors.Errorf("invalid private key length %d", len(b))
	}
	// Derive public key from private key
	edpk := ed25519.PrivateKey(b)
	publicKey := edpk.Public().(ed25519.PublicKey)
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.Errorf("invalid public key bytes (len=%d)", len(publicKey))
	}

	var privateKeyBytes [ed25519.PrivateKeySize]byte
	copy(privateKeyBytes[:], b[:ed25519.PrivateKeySize])

	var publicKeyBytes [ed25519.PublicKeySize]byte
	copy(publicKeyBytes[:], publicKey[:ed25519.PublicKeySize])

	k.privateKey = &privateKeyBytes
	k.publicKey = NewEdX25519PublicKey(&publicKeyBytes)
	return nil
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
func (k *EdX25519Key) ID() ID {
	return k.publicKey.ID()
}

// Type ...
func (k *EdX25519Key) Type() KeyType {
	return EdX25519
}

// Private ...
func (k *EdX25519Key) Private() []byte {
	return k.privateKey[:]
}

// Public ...
func (k *EdX25519Key) Public() []byte {
	return k.PublicKey().Public()
}

// Signer interface.
func (k *EdX25519Key) Signer() crypto.Signer {
	return ed25519.PrivateKey(k.Private())
}

func (k *EdX25519Key) PaperKey() string {
	s, err := encoding.BytesToPhrase(k.Seed()[:])
	if err != nil {
		panic(err)
	}
	return s
}

// MarshalText for encoding.TextMarshaler interface.
func (k *EdX25519Key) MarshalText() ([]byte, error) {
	return []byte(encoding.MustEncode(k.Seed()[:], encoding.Base64)), nil
}

// UnmarshalText for encoding.TextUnmarshaler interface.
func (k *EdX25519Key) UnmarshalText(s []byte) error {
	b, err := encoding.Decode(string(s), encoding.Base64)
	if err != nil {
		return err
	}
	var privateKey []byte
	if len(b) == 32 {
		privateKey = ed25519.NewKeyFromSeed(b)
	} else {
		privateKey = b
	}
	if err := k.setPrivateKey(privateKey); err != nil {
		return err
	}
	return nil
}

// Equal returns true if equal to key.
func (k *EdX25519Key) Equal(o *EdX25519Key) bool {
	return subtle.ConstantTimeCompare(k.Private(), o.Private()) == 1
}

// NewEdX25519PublicKey creates a EdX25519PublicKey.
func NewEdX25519PublicKey(b *[ed25519.PublicKeySize]byte) *EdX25519PublicKey {
	return &EdX25519PublicKey{
		id:        MustID(edx25519KeyHRP, b[:]),
		publicKey: b,
	}
}

// NewEdX25519PublicKeyFromID creates a EdX25519PublicKey from an ID.
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

// X25519Match returns true if key IDs are equal or if either key matches their
// X25519 counterpart.
func X25519Match(expected ID, kid ID) bool {
	if expected == kid {
		return true
	}
	if expected.IsEdX25519() && kid.IsX25519() {
		spk, err := NewEdX25519PublicKeyFromID(expected)
		if err != nil {
			return false
		}
		return kid == spk.X25519PublicKey().ID()
	}
	if kid.IsEdX25519() && expected.IsX25519() {
		spk, err := NewEdX25519PublicKeyFromID(kid)
		if err != nil {
			return false
		}
		return expected == spk.X25519PublicKey().ID()
	}
	return false
}

// ID for EdX25519Key.
func (k *EdX25519PublicKey) ID() ID {
	return k.id
}

func (k *EdX25519PublicKey) String() string {
	return k.id.String()
}

// Type ...
func (k *EdX25519PublicKey) Type() KeyType {
	return EdX25519
}

// Bytes ...
func (k *EdX25519PublicKey) Bytes() []byte {
	return k.publicKey[:]
}

// Public ...
func (k *EdX25519PublicKey) Public() []byte {
	return k.Bytes()
}

// Private returns nil.
func (k *EdX25519PublicKey) Private() []byte {
	return nil
}

// X25519PublicKey converts the ed25519 public key to a x25519 public key.
func (k *EdX25519PublicKey) X25519PublicKey() *X25519PublicKey {
	edpk := ed25519.PublicKey(k.publicKey[:])
	bpk := ed25519PublicKeyToCurve25519(edpk)
	if len(bpk) != 32 {
		panic("unable to convert key: invalid public key bytes")
	}
	key := NewX25519PublicKey(Bytes32(bpk))
	// TODO: Copy metadata?
	// key.metadata = s.metadata
	return key
}

// Verify verifies a message and signature with public key and returns the
// signed bytes without the signature.
func (k *EdX25519PublicKey) Verify(b []byte) ([]byte, error) {
	if l := len(b); l < sign.Overhead {
		return nil, errors.Errorf("not enough data for signature")
	}
	_, ok := sign.Open(nil, b, k.publicKey)
	if !ok {
		return nil, ErrVerifyFailed
	}
	return b[sign.Overhead:], nil
}

// VerifyDetached verifies a detached message.
func (k *EdX25519PublicKey) VerifyDetached(sig []byte, b []byte) error {
	if len(sig) != sign.Overhead {
		return errors.Errorf("invalid sig bytes length")
	}
	if len(b) == 0 {
		return errors.Errorf("no bytes")
	}
	msg := bytesJoin(sig, b)
	_, err := k.Verify(msg)
	return err
}

// NewEdX25519KeyFromSeed constructs EdX25519Key from an ed25519 seed.
// The private key is derived from this seed and the public key is derived from the private key.
func NewEdX25519KeyFromSeed(seed *[ed25519.SeedSize]byte) *EdX25519Key {
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return NewEdX25519KeyFromPrivateKey(Bytes64(privateKey))
}

// Seed returns information on how to generate this key from ed25519 package seed.
func (k *EdX25519Key) Seed() *[ed25519.SeedSize]byte {
	pk := ed25519.PrivateKey(k.privateKey[:])
	return Bytes32(pk.Seed())
}

func (k *EdX25519Key) String() string {
	return k.publicKey.String()
}

// PublicKey returns public part.
func (k *EdX25519Key) PublicKey() *EdX25519PublicKey {
	return k.publicKey
}

// PrivateKey returns private key part.
func (k *EdX25519Key) PrivateKey() *[ed25519.PrivateKeySize]byte {
	return k.privateKey
}

// Sign bytes with the (sign) private key.
func (k *EdX25519Key) Sign(b []byte) []byte {
	return sign.Sign(nil, b, k.privateKey)
}

// SignDetached sign bytes detached.
func (k *EdX25519Key) SignDetached(b []byte) []byte {
	return k.Sign(b)[:sign.Overhead]
}

// GenerateEdX25519Key generates a EdX25519Key (EdX25519).
func GenerateEdX25519Key() *EdX25519Key {
	logger.Infof("Generating EdX25519 key...")
	seed := Rand32()
	key := NewEdX25519KeyFromSeed(seed)
	return key
}
