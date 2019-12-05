package saltpack

import (
	"io"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// Seal ...
func (s *Saltpack) Seal(b []byte, sender keys.Key, recipients ...keys.PublicKey) ([]byte, error) {
	switch s.mode {
	case SigncryptMode:
		return s.Signcrypt(b, sender, recipients...)
	default:
		return nil, errors.Errorf("unrecognized mode")
	}
}

// Open decrypts data encrypted by Seal.
func (s *Saltpack) Open(b []byte) ([]byte, keys.ID, error) {
	switch s.mode {
	case SigncryptMode:
		return s.SigncryptOpen(b)
	default:
		return nil, "", errors.Errorf("unrecognized mode")
	}
}

// NewSealStream returns an io.Writer capable of encrypting data.
func (s *Saltpack) NewSealStream(w io.Writer, sender keys.Key, recipients ...keys.PublicKey) (io.WriteCloser, error) {
	switch s.mode {
	case SigncryptMode:
		return s.NewSigncryptStream(w, sender, recipients...)
	default:
		return nil, errors.Errorf("unrecognized mode")
	}
}

// NewOpenStream returns a io.Reader capable of decrypting data.
func (s *Saltpack) NewOpenStream(r io.Reader) (io.Reader, keys.ID, error) {
	switch s.mode {
	case SigncryptMode:
		return s.NewSigncryptOpenStream(r)
	default:
		return nil, "", errors.Errorf("unrecognized mode")
	}
}
