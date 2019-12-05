package saltpack

import (
	"bytes"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"
)

// BoxKey is a wrapper for keys.BoxKey to support a ksaltpack.BoxKey.
type BoxKey struct {
	ksaltpack.BoxSecretKey
	id         keys.ID
	privateKey keys.BoxPrivateKey
	publicKey  *BoxPublicKey
}

// GenerateBoxKey creates a BoxKey.
func GenerateBoxKey() BoxKey {
	bk := keys.GenerateBoxKey()
	return NewBoxKey(bk)
}

// NewBoxKey creates a BoxKey from a keys.BoxKey.
func NewBoxKey(bk *keys.BoxKey) BoxKey {
	pk := NewBoxPublicKey(bk.PublicKey)
	return BoxKey{
		privateKey: bk.PrivateKey(),
		publicKey:  pk,
	}
}

// Box (for ksaltpack.BoxSecretKey)
func (k BoxKey) Box(receiver ksaltpack.BoxPublicKey, nonce ksaltpack.Nonce, msg []byte) []byte {
	ret := box.Seal([]byte{}, msg, (*[24]byte)(&nonce),
		(*[32]byte)(receiver.ToRawBoxKeyPointer()), (*[32]byte)(k.privateKey))
	return ret
}

// Unbox (for ksaltpack.BoxSecretKey)
func (k BoxKey) Unbox(sender ksaltpack.BoxPublicKey, nonce ksaltpack.Nonce, msg []byte) ([]byte, error) {
	out, ok := box.Open([]byte{}, msg, (*[24]byte)(&nonce),
		(*[32]byte)(sender.ToRawBoxKeyPointer()), (*[32]byte)(k.privateKey))
	if !ok {
		return nil, errors.Errorf("public key decryption failed")
	}
	return out, nil
}

// GetPublicKey (for ksaltpack.BoxSecretKey)
func (k BoxKey) GetPublicKey() ksaltpack.BoxPublicKey {
	return k.publicKey
}

// Precompute (for ksaltpack.BoxSecretKey)
func (k BoxKey) Precompute(peer ksaltpack.BoxPublicKey) ksaltpack.BoxPrecomputedSharedKey {
	var res boxPrecomputedSharedKey
	box.Precompute((*[32]byte)(&res), (*[32]byte)(peer.ToRawBoxKeyPointer()), (*[32]byte)(k.privateKey))
	return res
}

// BoxPublicKey is a wrapper for keys.BoxPublicKey to support a ksaltpack.BoxPublicKey.
type BoxPublicKey struct {
	ksaltpack.BoxPublicKey
	pk keys.BoxPublicKey
}

// NewBoxPublicKey from byte array.
func NewBoxPublicKey(pk keys.BoxPublicKey) *BoxPublicKey {
	return &BoxPublicKey{pk: pk}
}

// ToKID (for ksaltpack.BoxPublicKey)
func (p *BoxPublicKey) ToKID() []byte {
	return p.pk[:]
}

func boxPublicKeyFromKID(b []byte) *BoxPublicKey {
	if len(b) != 32 {
		logger.Errorf("Invalid box public key bytes")
		return nil
	}
	pk := keys.Bytes32(b)
	return NewBoxPublicKey(keys.BoxPublicKey(pk))
}

// ToRawBoxKeyPointer (for ksaltpack.BoxPublicKey)
func (p *BoxPublicKey) ToRawBoxKeyPointer() *ksaltpack.RawBoxKey {
	rbk := ksaltpack.RawBoxKey(*p.pk)
	return &rbk
}

// CreateEphemeralKey (for ksaltpack.BoxPublicKey)
func (p *BoxPublicKey) CreateEphemeralKey() (ksaltpack.BoxSecretKey, error) {
	bk := GenerateBoxKey()
	return bk, nil
}

// HideIdentity (for ksaltpack.BoxPublicKey)
func (p *BoxPublicKey) HideIdentity() bool {
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
