package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
)

// P256 key.
const P256 KeyType = "p256"
const p256KeyHRP string = "kpa"

// P256Public public key.
const P256Public KeyType = "p256-public"

// P256PublicKey ...
type P256PublicKey struct {
	id        ID
	publicKey *ecdsa.PublicKey
}

// P256Key is a P-256 key capable of signing.
type P256Key struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *P256PublicKey
}

// GenerateP256Key ...
func GenerateP256Key() *P256Key {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	return &P256Key{
		privateKey: priv,
		publicKey: &P256PublicKey{
			publicKey: priv.Public().(*ecdsa.PublicKey),
		},
	}
}

// Sign data using p256/sha512.
func (k *P256Key) Sign(data []byte) ([]byte, error) {
	digest := sha512.Sum512(data)

	// sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, k.privateKey, digest[:])
	if err != nil {
		return nil, err
	}

	// encode the signature {R, S}
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	params := k.privateKey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return signature, nil
}

// Verify checks a raw ECDSA signature.
// Returns true if it's valid and false if not.
func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	// hash message
	digest := sha512.Sum512(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}
