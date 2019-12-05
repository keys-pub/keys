package keys

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// Key for signing and encryption.
type Key interface {
	// ID for key, which is equal to the Base58 encoded sign public key bytes.
	ID() ID
	// Seed used to generate the sign and box key material.
	Seed() *[32]byte
	// SignKey for signing. The signing key remains fixed.
	SignKey() *SignKey
	// BoxKey for (assymetric encryption).
	BoxKey() *BoxKey
	// SecretKey for (symmetric) encryption.
	SecretKey() SecretKey

	// PublicKey is the public parts of this key.
	PublicKey() PublicKey
}

// GenerateKey generates a new Key.
func GenerateKey() Key {
	seed := Rand32()
	key, err := NewKey(seed)
	if err != nil {
		panic(err)
	}
	logger.Infof("Generated key %s", key.ID())
	return key
}

type key struct {
	id   ID
	seed *[32]byte
	sik  *SignKey
	bk   *BoxKey
	sek  SecretKey
	pk   PublicKey
}

func (k key) ID() ID {
	return k.id
}

func (k key) Seed() *[32]byte {
	return k.seed
}

func (k key) BoxKey() *BoxKey {
	return k.bk
}

func (k key) SignKey() *SignKey {
	return k.sik
}

func (k key) SecretKey() SecretKey {
	return k.sek
}

func (k key) PublicKey() PublicKey {
	return k.pk
}

type publicKey struct {
	id    ID
	spk   SignPublicKey
	bpk   BoxPublicKey
	users []*User
}

func (p publicKey) ID() ID {
	return p.id
}

func (p publicKey) SignPublicKey() SignPublicKey {
	return p.spk
}

func (p publicKey) BoxPublicKey() BoxPublicKey {
	return p.bpk
}

func (p publicKey) Users() []*User {
	return p.users
}

// PublicKey defines a public key parts.
type PublicKey interface {
	// ID is the key identifier.
	ID() ID
	// SignPublicKey is the sign public key.
	SignPublicKey() SignPublicKey
	// BoxPublicKey is the (current) encryption public key.
	BoxPublicKey() BoxPublicKey
	// User (statements) signed with this key (optional).
	Users() []*User
}

// SeedPhrase returns a BIP39 mnemonic representation of the seed.
func SeedPhrase(key Key) string {
	phrase, err := BytesToPhrase(key.Seed()[:])
	if err != nil {
		panic(err)
	}
	return phrase
}

// HMACSHA256 does a HMAC-SHA256 on msg with key.
func HMACSHA256(key []byte, msg []byte) []byte {
	if len(key) == 0 {
		panic("empty hmac key")
	}
	if len(msg) == 0 {
		panic("empty hmac msg")
	}
	h := hmac.New(sha256.New, key)
	n, err := h.Write(msg)
	if err != nil {
		panic(err)
	}
	if n != len(msg) {
		panic("failed to write all bytes")
	}
	out := h.Sum(nil)
	if len(out) == 0 {
		panic("empty bytes")
	}
	return out
}

// deriveKey takes a seed and a string and derives a new key.
// The key is derived in the same way as a [Keybase Per-User Key
// (PUK)](https://keybase.io/docs/teams/puk) with the same inputs.
func deriveKey(seed *[32]byte, s string) *[32]byte {
	out := HMACSHA256(seed[:], []byte(s))
	return Bytes32(out)
}

func deriveSigningKey(seed *[32]byte) *[32]byte {
	return deriveKey(seed, "Derived-User-NaCl-EdDSA-1")
}

func deriveBoxKey(seed *[32]byte) *[32]byte {
	return deriveKey(seed, "Derived-User-NaCl-DH-1")
}

func deriveSecretKey(seed *[32]byte) *[32]byte {
	return deriveKey(seed, "Derived-User-NaCl-SecretBox-1")
}

// NewKey creates a Key from seed bytes. To create a new Key, see GenerateKey,
// which calls this with random seed bytes.
//
// The key is derived in the same way as a [Keybase Per-User Key
// (PUK)](https://keybase.io/docs/teams/puk).
//
// We keep the seed available, for generating a (BIP39) recovery phrase (see
// SeedPhrase). This phrase can be used to recover a Key.
func NewKey(seed *[32]byte) (Key, error) {
	signKeySeed := deriveSigningKey(seed)
	signKey, err := NewSignKeyFromSeed(signKeySeed)
	if err != nil {
		return nil, err
	}
	boxPrivateKey := deriveBoxKey(seed)
	boxKey := NewBoxKeyFromPrivateKey(boxPrivateKey)
	secretKey := deriveSecretKey(seed)

	k := &key{
		seed: seed,
		id:   signKey.ID,
		bk:   boxKey,
		sik:  signKey,
		sek:  secretKey,
		pk: &publicKey{
			id:  SignPublicKeyID(signKey.PublicKey),
			spk: signKey.PublicKey,
			bpk: boxKey.PublicKey,
		},
	}
	return k, nil
}

// NewKeyFromSeedPhrase creates Key from bip39 phrase of the seed.
func NewKeyFromSeedPhrase(seedPhrase string, sanitize bool) (Key, error) {
	seed, err := PhraseToBytes(seedPhrase, sanitize)
	if err != nil {
		return nil, err
	}
	if l := len(seed); l != SeedSize {
		return nil, errors.Errorf("invalid seed length from phrase")
	}
	return NewKey(seed)
}

// NewKeyFromPassword creates a key from a password.
func NewKeyFromPassword(password string, salt []byte) (Key, error) {
	if len(password) < 10 {
		return nil, errors.Errorf("password too short")
	}
	if len(salt) < 32 {
		return nil, errors.Errorf("not enough salt")
	}
	pwkey := argon2.IDKey([]byte(password), salt[:], 1, 64*1024, 4, 32)
	return NewKey(Bytes32(pwkey))
}
