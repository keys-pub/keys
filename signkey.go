package keys

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/sign"
)

// SignKeySize is the size of the SignKey private key bytes.
const SignKeySize = 64

// SignPublicKeySize is the size of the SignKey public key bytes.
const SignPublicKeySize = 32

// SeedSize is the size of the SignKey seed bytes.
const SeedSize = 32

// SignPrivateKey is the private part of nacl.sign key pair.
type SignPrivateKey *[SignKeySize]byte

// SignPublicKey is the public part of nacl.sign key pair.
type SignPublicKey *[SignPublicKeySize]byte

// SignKey a public/private boxKey which can sign and verify using nacl.sign.
type SignKey struct {
	privateKey SignPrivateKey
	PublicKey  SignPublicKey
	ID         ID
}

var emptySignKey = bytes.Repeat([]byte{0x00}, SignKeySize)

// NewSignKey constructs SignKey from a private key.
// The public key is derived from the private key.
func NewSignKey(privateKey []byte) (*SignKey, error) {
	if len(privateKey) != SignKeySize {
		return nil, errors.Errorf("invalid private key length %d", len(privateKey))
	}

	// Make sure private key isn't empty bytes
	if subtle.ConstantTimeCompare(privateKey, emptySignKey) == 1 {
		return nil, errors.Errorf("empty private key bytes")
	}

	// Derive public key from private key
	edpk := ed25519.PrivateKey(privateKey)
	publicKey := edpk.Public().(ed25519.PublicKey)
	if len(publicKey) != SignPublicKeySize {
		return nil, errors.Errorf("invalid public key bytes (len=%d)", len(publicKey))
	}

	var privateKeyBytes [SignKeySize]byte
	copy(privateKeyBytes[:], privateKey[:SignKeySize])

	var publicKeyBytes [SignPublicKeySize]byte
	copy(publicKeyBytes[:], publicKey[:SignPublicKeySize])

	return &SignKey{
		privateKey: &privateKeyBytes,
		PublicKey:  &publicKeyBytes,
		ID:         SignPublicKeyID(&publicKeyBytes),
	}, nil
}

// SignPublicKeyID returns ID for SignPublicKey.
func SignPublicKeyID(spk SignPublicKey) ID {
	return MustID(spk[:])
}

// EncodeSignPublicKey encodes SignPublicKey as a string.
func EncodeSignPublicKey(spk SignPublicKey) string {
	return MustEncode(spk[:], Base58)
}

// DecodeSignPublicKey returns SignPublicKey from a string.
func DecodeSignPublicKey(s string) (SignPublicKey, error) {
	b, err := Decode(s, Base58)
	if err != nil {
		return nil, err
	}
	if len(b) != SignPublicKeySize {
		return nil, errors.Errorf("invalid sign public key bytes")
	}
	return Bytes32(b), nil
}

// NewSignKeyFromSeed constructs SignKey from an ed25519 seed.
// The private key is derived from this seed and the public key is derived from the private key.
func NewSignKeyFromSeed(seed *[SeedSize]byte) (*SignKey, error) {
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return NewSignKey(privateKey)
}

// NewSignKeyFromHexString creates SignKey from hex encoded string (of private key).
func NewSignKeyFromHexString(s string) (*SignKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode sign key")
	}
	return NewSignKey(b)
}

// NewSignKeyFromSeedPhrase creates SignKey from bip39 phrase of the nacl.sign seed.
func NewSignKeyFromSeedPhrase(seedPhrase string, sanitize bool) (*SignKey, error) {
	seed, err := PhraseToBytes(seedPhrase, sanitize)
	if err != nil {
		return nil, err
	}
	if l := len(seed); l != SeedSize {
		return nil, errors.Errorf("invalid seed length from phrase")
	}
	return NewSignKeyFromSeed(seed)
}

// Seed returns information on how to generate this key from ed25519 package seed.
func (k SignKey) Seed() []byte {
	pk := ed25519.PrivateKey(k.privateKey[:])
	return pk.Seed()
}

// SeedPhrase returns bip39 phrase.
func (k SignKey) SeedPhrase() string {
	s, _ := BytesToPhrase(k.Seed())
	return s
}

// PrivateKey returns private key part.
func (k SignKey) PrivateKey() *[SignKeySize]byte {
	return k.privateKey
}

// Sign bytes with the (sign) private key.
func (k *SignKey) Sign(b []byte) []byte {
	return Sign(b, k)
}

// SignDetached sign bytes detached.
func (k *SignKey) SignDetached(b []byte) []byte {
	return SignDetached(b, k)
}

// Sign bytes.
func Sign(b []byte, sk *SignKey) []byte {
	return sign.Sign(nil, b, sk.privateKey)
}

// SignDetached sign bytes detached.
func SignDetached(b []byte, sk *SignKey) []byte {
	return Sign(b, sk)[:sign.Overhead]
}

// Verify verifies a message and signature with public key.
func Verify(b []byte, spk SignPublicKey) ([]byte, error) {
	if l := len(b); l < sign.Overhead {
		return nil, errors.Errorf("not enough data for signature")
	}
	_, ok := sign.Open(nil, b, spk)
	if !ok {
		return nil, errors.Errorf("verify failed")
	}
	return b[sign.Overhead:], nil
}

// VerifyDetached verifies a detached message.
func VerifyDetached(sig []byte, b []byte, spk SignPublicKey) error {
	if len(sig) != sign.Overhead {
		return errors.Errorf("invalid sig bytes length")
	}
	if len(b) == 0 {
		return errors.Errorf("no bytes")
	}
	msg := bytesJoin(sig, b)
	_, err := Verify(msg, spk)
	return err
}

// GenerateSignKey generates a SignKey (using ed25519).
func GenerateSignKey() *SignKey {
	logger.Infof("Generating ed25519 key...")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	sk, err := NewSignKey(privateKey)
	if err != nil {
		panic(err)
	}
	return sk
}
