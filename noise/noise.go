package noise

import (
	"github.com/flynn/noise"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// Cipher provides symmetric encryption and decryption after a successful
// handshake.
type Cipher interface {
	Encrypt(out, ad, plaintext []byte) ([]byte, error)
	Decrypt(out, ad, ciphertext []byte) ([]byte, error)
}

// Noise protocol for keys.pub.
// See http://www.noiseprotocol.org/.
type Handshake struct {
	initiator bool
	state     *noise.HandshakeState

	csI0 *noise.CipherState
	csI1 *noise.CipherState
	csR0 *noise.CipherState
	csR1 *noise.CipherState
}

// NewHandshake returns Handshake for X25519Key sender and recipient.
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
// (1) Initiator: Write
// (2) Responder: Read
// (3) Initiator: Read
// (4) Responder: Write
//
// Then handshake is complete (HandshakeComplete) and you will be able to Encrypt and Decrypt.
//
func NewHandshake(sender *keys.X25519Key, recipient *keys.X25519PublicKey, initiator bool) (*Handshake, error) {
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

	return &Handshake{
		initiator: initiator,
		state:     state,
	}, nil
}

// Write performs handshake write.
// You can include optional payload bytes, as the pattern allows zero-RTT
// encryption, meaning the initiator can encrypt the first handshake payload.
//
// The order of the handshake writes/reads should be:
// (1) Initiator: Write
// (2) Responder: Read
// (3) Initiator: Read
// (4) Responder: Write
func (n *Handshake) Write(payload []byte) ([]byte, error) {
	if n.Complete() {
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

// Read performs handshake read, returning optional payload if it was included
// in the Write, as the pattern allows zero-RTT encryption, meaning the
// initiator can encrypt the first handshake payload.
//
// The order of the handshake writes/reads should be:
// (1) Initiator: Write
// (2) Responder: Read
// (3) Initiator: Read
// (4) Responder: Write
func (n *Handshake) Read(b []byte) ([]byte, error) {
	if n.Complete() {
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

// Complete returns true if handshake is complete and Encrypt/Decrypt
// are available.
func (n *Handshake) Complete() bool {
	return n.csI0 != nil || n.csR0 != nil
}

// Cipher provides symmetric encryption and decryption after a successful
// handshake.
func (n *Handshake) Cipher() (Cipher, error) {
	if !n.Complete() {
		return nil, errors.Errorf("handshake not complete")
	}
	return newCipherState(n), nil
}
