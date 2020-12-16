package keys

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"
)

// BoxSeal uses nacl.box to encrypt.
func BoxSeal(b []byte, recipient *X25519PublicKey, sender *X25519Key) []byte {
	nonce := Rand24()
	return sealBox(b, nonce, recipient, sender)
}

func sealBox(b []byte, nonce *[24]byte, recipient *X25519PublicKey, sender *X25519Key) []byte {
	encrypted := box.Seal(nil, b, nonce, recipient.Bytes32(), sender.PrivateKey())
	return append(nonce[:], encrypted...)
}

// BoxOpen uses nacl.box to decrypt.
func BoxOpen(encrypted []byte, sender *X25519PublicKey, recipient *X25519Key) ([]byte, error) {
	return openBox(encrypted, sender, recipient)
}

func openBox(encrypted []byte, sender *X25519PublicKey, recipient *X25519Key) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, errors.Errorf("not enough bytes")
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	encrypted = encrypted[24:]

	b, ok := box.Open(nil, encrypted, &nonce, sender.Bytes32(), recipient.PrivateKey())
	if !ok {
		return nil, errors.Errorf("box open failed")
	}
	return b, nil
}
