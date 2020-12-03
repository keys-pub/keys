package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

// RSA key type.
const RSA KeyType = "rsa"
const rsaKeyHRP = "rsa"

// RSAPublicKey is the public part of RSA key pair.
type RSAPublicKey struct {
	id ID
	pk *rsa.PublicKey
}

// RSAKey implements Key interface for RSA.
type RSAKey struct {
	privateKey *rsa.PrivateKey
	publicKey  *RSAPublicKey
}

// NewRSAKeyFromBytes constructs RSA from a private key (PKCS1).
func NewRSAKeyFromBytes(privateKey []byte) (*RSAKey, error) {
	k, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return NewRSAKey(k), nil
}

func keyIDFromRSA(k *rsa.PublicKey) ID {
	// SHA256 of PKCS1 public key
	b := x509.MarshalPKCS1PublicKey(k)
	hasher := crypto.SHA256.New()
	_, err := hasher.Write(b)
	if err != nil {
		panic(err)
	}
	return MustID(rsaKeyHRP, hasher.Sum(nil))
}

// NewRSAKey from rsa.PrivateKey.
func NewRSAKey(k *rsa.PrivateKey) *RSAKey {
	pk := NewRSAPublicKey(&k.PublicKey)
	return &RSAKey{k, pk}
}

// PublicKey ...
func (k *RSAKey) PublicKey() *RSAPublicKey {
	return k.publicKey
}

// ID for the key.
func (k *RSAKey) ID() ID {
	return k.publicKey.ID()
}

// Type of key.
func (k *RSAKey) Type() KeyType {
	return RSA
}

// Private key data (PKCS1).
func (k *RSAKey) Private() []byte {
	return x509.MarshalPKCS1PrivateKey(k.privateKey)
}

// Public key data (PKCS1).
func (k *RSAKey) Public() []byte {
	return k.publicKey.Public()
}

// NewRSAPublicKey returns RSA public key.
func NewRSAPublicKey(pk *rsa.PublicKey) *RSAPublicKey {
	id := keyIDFromRSA(pk)
	return &RSAPublicKey{id, pk}
}

// NewRSAPublicKeyFromBytes returns RSA public key from PKC1 bytes.
func NewRSAPublicKeyFromBytes(publicKey []byte) (*RSAPublicKey, error) {
	pk, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return NewRSAPublicKey(pk), nil
}

// ID is key identifier.
func (k *RSAPublicKey) ID() ID {
	return k.id
}

// Bytes for public key (PKCS1).
func (k *RSAPublicKey) Bytes() []byte {
	return x509.MarshalPKCS1PublicKey(k.pk)
}

// Public key data.
func (k *RSAPublicKey) Public() []byte {
	return k.Bytes()
}

// Private returns nil.
func (k *RSAPublicKey) Private() []byte {
	return nil
}

// Type of key.
func (k *RSAPublicKey) Type() KeyType {
	return RSA
}

// GenerateRSAKey generates a RSA key.
func GenerateRSAKey() *RSAKey {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
	return NewRSAKey(priv)
}
