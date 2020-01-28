package saltpack

import (
	"bytes"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"
)

// boxKey is a wrapper for keys.BoxKey to support a ksaltpack.BoxKey.
type boxKey struct {
	ksaltpack.BoxSecretKey
	privateKey *[32]byte
	publicKey  *boxPublicKey
}

// GenerateBoxKey creates a BoxKey.
func generateBoxKey() boxKey {
	bk := keys.GenerateX25519Key()
	return newBoxKey(bk)
}

// newBoxKey creates a BoxKey from a keys.BoxKey.
func newBoxKey(bk *keys.BoxKey) boxKey {
	pk := newBoxPublicKey(bk.PublicKey())
	return boxKey{
		privateKey: bk.PrivateKey(),
		publicKey:  pk,
	}
}

// Box (for ksaltpack.BoxSecretKey)
func (k boxKey) Box(receiver ksaltpack.BoxPublicKey, nonce ksaltpack.Nonce, msg []byte) []byte {
	ret := box.Seal([]byte{}, msg, (*[24]byte)(&nonce),
		(*[32]byte)(receiver.ToRawBoxKeyPointer()), (*[32]byte)(k.privateKey))
	return ret
}

// Unbox (for ksaltpack.BoxSecretKey)
func (k boxKey) Unbox(sender ksaltpack.BoxPublicKey, nonce ksaltpack.Nonce, msg []byte) ([]byte, error) {
	out, ok := box.Open([]byte{}, msg, (*[24]byte)(&nonce),
		(*[32]byte)(sender.ToRawBoxKeyPointer()), (*[32]byte)(k.privateKey))
	if !ok {
		return nil, errors.Errorf("public key decryption failed")
	}
	return out, nil
}

// GetPublicKey (for ksaltpack.BoxSecretKey)
func (k boxKey) GetPublicKey() ksaltpack.BoxPublicKey {
	return k.publicKey
}

// Precompute (for ksaltpack.BoxSecretKey)
func (k boxKey) Precompute(peer ksaltpack.BoxPublicKey) ksaltpack.BoxPrecomputedSharedKey {
	var res boxPrecomputedSharedKey
	box.Precompute((*[32]byte)(&res), (*[32]byte)(peer.ToRawBoxKeyPointer()), (*[32]byte)(k.privateKey))
	return res
}

// boxPublicKey is a wrapper for keys.BoxPublicKey to support a ksaltpack.BoxPublicKey.
type boxPublicKey struct {
	ksaltpack.BoxPublicKey
	pk *keys.BoxPublicKey
}

// newBoxPublicKey from byte array.
func newBoxPublicKey(pk *keys.BoxPublicKey) *boxPublicKey {
	return &boxPublicKey{pk: pk}
}

// ToKID (for ksaltpack.BoxPublicKey)
func (p *boxPublicKey) ToKID() []byte {
	return p.pk.Bytes()[:]
}

func boxPublicKeyFromKID(b []byte) *boxPublicKey {
	if len(b) != 32 {
		logger.Errorf("Invalid box public key bytes")
		return nil
	}
	pk := keys.Bytes32(b)
	return newBoxPublicKey(keys.NewX25519PublicKey(pk))
}

// ToRawBoxKeyPointer (for ksaltpack.BoxPublicKey)
func (p *boxPublicKey) ToRawBoxKeyPointer() *ksaltpack.RawBoxKey {
	rbk := ksaltpack.RawBoxKey(*p.pk.Bytes32())
	return &rbk
}

// CreateEphemeralKey (for ksaltpack.BoxPublicKey)
func (p *boxPublicKey) CreateEphemeralKey() (ksaltpack.BoxSecretKey, error) {
	bk := generateBoxKey()
	return bk, nil
}

// HideIdentity (for ksaltpack.BoxPublicKey)
func (p *boxPublicKey) HideIdentity() bool {
	// TODO: Make configurable
	return true
}

type boxPrecomputedSharedKey [32]byte

func (b boxPrecomputedSharedKey) Unbox(nonce ksaltpack.Nonce, msg []byte) ([]byte, error) {
	out, ok := box.OpenAfterPrecomputation([]byte{}, msg, (*[24]byte)(&nonce), (*[32]byte)(&b))
	if !ok {
		return nil, errors.Errorf("public key decryption failed")
	}
	return out, nil
}

func (b boxPrecomputedSharedKey) Box(nonce ksaltpack.Nonce, msg []byte) []byte {
	out := box.SealAfterPrecomputation([]byte{}, msg, (*[24]byte)(&nonce), (*[32]byte)(&b))
	return out
}

func bytesJoin(b ...[]byte) []byte {
	return bytes.Join(b, []byte{})
}
