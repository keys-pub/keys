package keys

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/sign"
)

// CryptoProvider defines a provider for signing and encyption.
type CryptoProvider interface {
	SignProvider
	SealProvider
}

// SignProvider defines a provider for signing.
type SignProvider interface {
	// Sign data from a key.
	Sign(b []byte, key *SignKey) ([]byte, error)
	// Verify data for a public key.
	Verify(b []byte) ([]byte, SignPublicKey, error)
	// SignDetached data for a key.
	SignDetached(b []byte, key *SignKey) ([]byte, error)
	// VerifyDetached data for a public key.
	VerifyDetached(b []byte, sig []byte) (SignPublicKey, error)
}

// SealProvider defines a provider for encryption.
type SealProvider interface {
	// Seal encrypts data to recipients (public keys) from a sender (key).
	// For an anonymous sender, you can specify sender as nil.
	Seal(b []byte, sender Key, recipients ...PublicKey) ([]byte, error)
	// Open decrypts data encrypted by Seal.
	Open(b []byte) ([]byte, ID, error)
}

// CryptoStreamProvider defines a streaming provider for signing and encryption.
type CryptoStreamProvider interface {
	SignStreamProvider
	SealStreamProvider
}

// SignStreamProvider defines a streaming provider for signing.
type SignStreamProvider interface {
	// NewSignStream returns an io.Writer capable of signing data.
	NewSignStream(w io.Writer, key *SignKey, detached bool) (io.WriteCloser, error)
	// NewVerifyStream returns a io.Reader capable of verifying data.
	NewVerifyStream(r io.Reader) (io.Reader, SignPublicKey, error)
}

// SealStreamProvider defines a streaming provider for encryption.
type SealStreamProvider interface {
	// NewSealStream returns an io.Writer capable of encrypting data.
	NewSealStream(w io.Writer, sender Key, recipients ...PublicKey) (io.WriteCloser, error)
	// NewOpenStream returns a io.Reader capable of decrypting data.
	NewOpenStream(r io.Reader) (io.Reader, ID, error)
}

type naclProvider struct {
	ks *Keystore
}

// newBasicCryptoProvider returns a basic CryptoProvider which uses nacl.sign
// and nacl.box. You should probably use a more robust provider such as the
// one in [keys/saltpack](https://godoc.org/github.com/keys-pub/keys/saltpack).
// This basic provider can only encrypt to a single recipient and will not
// handle messages larger than 16KB. It doesn't support streaming or armoring.
func newBasicCryptoProvider(ks *Keystore) CryptoProvider {
	return &naclProvider{ks: ks}
}

// newBasicSignProvider returns a basic SignProvider which uses nacl.sign.
// You should probably use a more robust provider such as the
// one in [keys/saltpack](https://godoc.org/github.com/keys-pub/keys/saltpack).
// This basic provider can't handle messages larger than 16KB. It doesn't
// support streaming or armoring.
func newBasicSignProvider(ks *Keystore) SignProvider {
	return &naclProvider{ks: ks}
}

func (c naclProvider) Sign(b []byte, key *SignKey) ([]byte, error) {
	if len(b) > 16*1024 {
		return nil, errors.Errorf("signing large messages is not supported by this provider")
	}
	b = bytesJoin(key.ID.Bytes(), b)
	out := key.Sign(b)
	return out, nil
}

func (c naclProvider) Verify(b []byte) ([]byte, SignPublicKey, error) {
	if len(b) < sign.Overhead+32 {
		return nil, nil, errors.Errorf("failed to verify: not enough data")
	}
	kid, err := NewID(b[sign.Overhead : sign.Overhead+32])
	if err != nil {
		return nil, nil, err
	}
	spk, err := DecodeSignPublicKey(kid.String())
	if err != nil {
		return nil, nil, err
	}
	msg, err := Verify(b, spk)
	if err != nil {
		return nil, nil, err
	}
	return msg[32:], spk, nil
}

func (c naclProvider) SignDetached(b []byte, key *SignKey) ([]byte, error) {
	// TODO: Implement
	return nil, errors.Errorf("not implemented")
}

func (c naclProvider) VerifyDetached(sig []byte, b []byte) (SignPublicKey, error) {
	msg := bytesJoin(sig, b)
	_, pk, err := c.Verify(msg)
	return pk, err
}

func (c naclProvider) Seal(b []byte, sender Key, recipients ...PublicKey) ([]byte, error) {
	if len(b) > 16*1024 {
		return nil, errors.Errorf("encrypting large messages is not supported by this provider")
	}
	if len(recipients) == 0 {
		return nil, errors.Errorf("no recipients")
	}
	if len(recipients) > 1 {
		return nil, errors.Errorf("only a single recipient is supported by this provider")
	}
	if sender == nil {
		return nil, errors.Errorf("anonymous sender not supported")
	}

	sbk := sender.BoxKey()
	if sbk == nil {
		return nil, errors.Errorf("no sender box key")
	}

	rbpk := recipients[0].BoxPublicKey()
	if rbpk == nil {
		return nil, errors.Errorf("no recipient box public key")
	}

	nonce := Rand24()
	encrypted := sbk.Seal(b, nonce, rbpk)
	data := bytesJoin(sbk.PublicKey[:], nonce[:], encrypted)
	return c.Sign(data, sender.SignKey())
}

func (c naclProvider) Open(b []byte) ([]byte, ID, error) {
	verified, signer, err := c.Verify(b)
	if err != nil {
		return nil, "", err
	}

	if len(verified) < 32+24 {
		return nil, "", errors.Errorf("no enough data to open")
	}

	bid, err := NewID(verified[0:32])
	if err != nil {
		return nil, "", err
	}
	bpk, err := DecodeBoxPublicKey(bid.String())
	if err != nil {
		return nil, "", err
	}
	verified = verified[32:]

	ks, err := c.ks.Keys()
	if err != nil {
		return nil, "", err
	}

	var out []byte
	ok := false

open:
	for _, k := range ks {
		bk := k.BoxKey()
		if bk == nil {
			continue
		}
		nonce := Bytes24(verified[:24])
		encrypted := verified[24:]
		out, ok = bk.Open(encrypted, nonce, bpk)
		if ok {
			break open
		}
	}
	if !ok {
		return nil, "", errors.Errorf("open failed")
	}
	return out, SignPublicKeyID(signer), nil
}

func bytesJoin(b ...[]byte) []byte {
	return bytes.Join(b, []byte{})
}
