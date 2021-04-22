package noise

import (
	"github.com/pkg/errors"
)

type cipherState struct {
	*Handshake
}

func newCipherState(handshake *Handshake) cipherState {
	return cipherState{
		handshake,
	}
}

// Encrypt to out.
func (n cipherState) Encrypt(out, ad, plaintext []byte) ([]byte, error) {
	if n.initiator {
		if n.csI0 == nil {
			return nil, errors.Errorf("no cipher for encrypt (I)")
		}
		return n.csI0.Encrypt(out, ad, plaintext)
	}
	if n.csR1 == nil {
		return nil, errors.Errorf("no cipher for encrypt (R)")
	}
	return n.csR1.Encrypt(out, ad, plaintext)
}

// Decrypt to out.
func (n cipherState) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
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
