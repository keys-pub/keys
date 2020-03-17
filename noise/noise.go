package noise

import (
	"github.com/flynn/noise"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// Noise protocol for keys.pub.
// See http://www.noiseprotocol.org/.
type Noise struct {
	initiator bool
	state     *noise.HandshakeState
	csI0      *noise.CipherState
	csI1      *noise.CipherState
	csR0      *noise.CipherState
	csR1      *noise.CipherState
}

// NewNoise returns Noise for X25519Key sender and recipient.
//
// The cipher suite used is:
// Curve25519 ECDH, ChaCha20-Poly1305 AEAD, BLAKE2b hash.
//
// The handshake uses the KK pattern:
// K = Static key for initiator Known to responder
// K = Static key for responder Known to initiator
//
// One of the Noise participants should be the initiator.
//
// The order of the handshake writes/reads should be:
// (1) Initiator: HandshakeWrite
// (2) Responder: HandshakeRead
// (3) Initiator: HandshakeRead
// (4) Responder: HandshakeWrite
//
// Then handshake is complete (HandshakeComplete) and you will be able to Encrypt and Decrypt.
//
func NewNoise(sender *keys.X25519Key, recipient *keys.X25519PublicKey, initiator bool) (*Noise, error) {
	dhKey := noise.DHKey{
		Private: sender.PrivateKey()[:],
		Public:  sender.PublicKey().Bytes(),
	}
	pk := recipient.Bytes()

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	config := noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeKK,
		Initiator:     initiator,
		Prologue:      []byte("keys.pub/1.0"),
		StaticKeypair: dhKey,
		PeerStatic:    pk,
	}

	state, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	return &Noise{
		initiator: initiator,
		state:     state,
	}, nil
}

// HandshakeWrite performs handshake write.
// You can include optional payload bytes, as the pattern allows zero-RTT
// encryption, meaning the initiator can encrypt the first handshake payload.
//
// The order of the handshake writes/reads should be:
// (1) Initiator: HandshakeWrite
// (2) Responder: HandshakeRead
// (3) Initiator: HandshakeRead
// (4) Responder: HandshakeWrite
func (n *Noise) HandshakeWrite(payload []byte) ([]byte, error) {
	if n.HandshakeComplete() {
		return nil, errors.Errorf("handshake already complete")
	}
	out, csR0, csR1, err := n.state.WriteMessage(nil, payload)
	if err != nil {
		return nil, err
	}
	if !n.initiator {
		n.csR0 = csR0
		n.csR1 = csR1
	}
	return out, nil
}

// HandshakeRead performs handshake read, returning optional payload if it was
// included in the HandshakeWrite, as the pattern allows zero-RTT
// encryption, meaning the initiator can encrypt the first handshake payload.
//
// The order of the handshake writes/reads should be:
// (1) Initiator: HandshakeWrite
// (2) Responder: HandshakeRead
// (3) Initiator: HandshakeRead
// (4) Responder: HandshakeWrite
func (n *Noise) HandshakeRead(b []byte) ([]byte, error) {
	if n.HandshakeComplete() {
		return nil, errors.Errorf("handshake already complete")
	}
	out, csI0, csI1, err := n.state.ReadMessage(nil, b)
	if err != nil {
		return nil, err
	}
	if n.initiator {
		n.csI0 = csI0
		n.csI1 = csI1
	}
	return out, nil
}

// HandshakeComplete returns true if handshake is complete and Encrypt/Decrypt
// are available.
func (n *Noise) HandshakeComplete() bool {
	return n.csI0 != nil || n.csR0 != nil
}

// Encrypt to out.
func (n *Noise) Encrypt(out, ad, plaintext []byte) ([]byte, error) {
	if n.initiator {
		if n.csI0 == nil {
			return nil, errors.Errorf("no cipher for encrypt (I)")
		}
		return n.csI0.Encrypt(out, ad, plaintext), nil
	}
	if n.csR1 == nil {
		return nil, errors.Errorf("no cipher for encrypt (R)")
	}
	return n.csR1.Encrypt(out, ad, plaintext), nil
}

// Decrypt to out.
func (n *Noise) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	if n.initiator {
		if n.csI1 == nil {
			return nil, errors.Errorf("no cipher for decrypt (I)")
		}
		return n.csI1.Decrypt(out, ad, ciphertext)
	}
	if n.csR0 == nil {
		return nil, errors.Errorf("no cipher for decrypt (R)")
	}
	return n.csR0.Decrypt(out, ad, ciphertext)
}
