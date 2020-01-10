package keys

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"
)

// BoxSeal encrypts a message to a recipient.
func BoxSeal(b []byte, recipient *BoxPublicKey, sender *BoxKey) []byte {
	nonce := Rand24()
	return sealBox(b, nonce, recipient, sender)
}

func sealBox(b []byte, nonce *[24]byte, recipient *BoxPublicKey, sender *BoxKey) []byte {
	encrypted := box.Seal(nil, b, nonce, recipient.Bytes(), sender.PrivateKey())
	return append(nonce[:], encrypted...)
}

// BoxOpen decrypts a message from a sender.
func BoxOpen(encrypted []byte, sender *BoxPublicKey, recipient *BoxKey) ([]byte, error) {
	return openBox(encrypted, sender, recipient)
}

func openBox(encrypted []byte, sender *BoxPublicKey, recipient *BoxKey) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, errors.Errorf("not enough bytes")
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	encrypted = encrypted[24:]

	b, ok := box.Open(nil, encrypted, &nonce, sender.Bytes(), recipient.PrivateKey())
	if !ok {
		return nil, errors.Errorf("box open failed")
	}
	return b, nil
}
