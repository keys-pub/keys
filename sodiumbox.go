package keys

import (
	"crypto/rand"

	"github.com/dchest/blake2b"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"
)

func cryptoBoxSealNonce(ephemeralPk, publicKey *[32]byte) *[24]byte {
	nonce := new([24]byte)
	hashConfig := &blake2b.Config{Size: 24}
	hashFn, err := blake2b.New(hashConfig)
	if err != nil {
		panic("failed to create blake2b hash function")
	}
	_, _ = hashFn.Write(ephemeralPk[0:32])
	_, _ = hashFn.Write(publicKey[0:32])
	nonceSum := hashFn.Sum(nil)
	copy(nonce[:], nonceSum[0:24])
	return nonce
}

// CryptoBoxSeal implements libsodium crypto_box_seal.
func CryptoBoxSeal(b []byte, publicKey *X25519PublicKey) []byte {
	ephemeralPK, ephemeralSK, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic("failed to generate key")
	}
	nonce := cryptoBoxSealNonce(ephemeralPK, publicKey.Bytes32())
	boxed := box.Seal(nil, b, nonce, publicKey.Bytes32(), ephemeralSK)
	return append(ephemeralPK[:], boxed...)
}

// CryptoBoxSealOpen implements libsodium crypto_box_seal_open.
func CryptoBoxSealOpen(b []byte, key *X25519Key) ([]byte, error) {
	if len(b) < 32 {
		return nil, errors.Errorf("not enough data to box open")
	}
	ephemeralPK := Bytes32(b[:32])
	nonce := cryptoBoxSealNonce(ephemeralPK, key.PublicKey().Bytes32())
	result, ok := box.Open(nil, b[32:], nonce, ephemeralPK, key.Bytes32())
	if !ok {
		return nil, errors.Errorf("failed to box open")
	}
	return result, nil
}
