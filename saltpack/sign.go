package saltpack

import (
	"io"
	"strings"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// Sign ...
func (s *Saltpack) Sign(b []byte, key *keys.SignKey) ([]byte, error) {
	if s.armor {
		s, err := ksaltpack.SignArmor62(ksaltpack.Version1(), b, newSignKey(key), s.armorBrand)
		return []byte(s), err
	}
	return ksaltpack.Sign(ksaltpack.Version1(), b, newSignKey(key))
}

// SignDetached ...
func (s *Saltpack) SignDetached(b []byte, key *keys.SignKey) ([]byte, error) {
	if s.armor {
		// TODO: Implement
		return nil, errors.Errorf("not implemented")
	}
	return ksaltpack.SignDetached(ksaltpack.Version1(), b, newSignKey(key))
}

// Verify ...
func (s *Saltpack) Verify(b []byte) ([]byte, *keys.SignPublicKey, error) {
	if s.armor {
		return s.verifyArmored(string(b))
	}
	spk, out, err := ksaltpack.Verify(versionValidator, b, s)
	if err != nil {
		return nil, nil, convertErr(err)
	}

	return out, toSignPublicKey(spk), nil
}

func (s *Saltpack) verifyArmored(msg string) ([]byte, *keys.SignPublicKey, error) {
	spk, out, _, err := ksaltpack.Dearmor62Verify(versionValidator, msg, s)
	if err != nil {
		return nil, nil, convertErr(err)
	}
	return out, toSignPublicKey(spk), nil
}

func toSignPublicKey(spk ksaltpack.SigningPublicKey) *keys.SignPublicKey {
	b := spk.ToKID()
	if len(b) != keys.SignPublicKeySize {
		logger.Errorf("invalid sign public key bytes")
		return nil
	}
	return keys.NewSignPublicKey(keys.Bytes32(b))
}

// VerifyDetached ...
func (s *Saltpack) VerifyDetached(sig []byte, b []byte) (*keys.SignPublicKey, error) {
	if s.armor {
		// TODO: Implement
		return nil, errors.Errorf("not implemented")
	}
	spk, err := ksaltpack.VerifyDetached(versionValidator, b, sig, s)
	if err != nil {
		return nil, convertErr(err)
	}

	return toSignPublicKey(spk), nil
}

// NewSignStream ...
func (s *Saltpack) NewSignStream(w io.Writer, key *keys.SignKey, detached bool) (io.WriteCloser, error) {
	if detached && s.armor {
		return ksaltpack.NewSignDetachedArmor62Stream(ksaltpack.Version1(), w, newSignKey(key), s.armorBrand)
	}
	if s.armor {
		return ksaltpack.NewSignArmor62Stream(ksaltpack.Version1(), w, newSignKey(key), s.armorBrand)
	}
	if detached {
		return ksaltpack.NewSignDetachedStream(ksaltpack.Version1(), w, newSignKey(key))
	}
	return ksaltpack.NewSignStream(ksaltpack.Version1(), w, newSignKey(key))
}

// NewVerifyStream ...
func (s *Saltpack) NewVerifyStream(r io.Reader) (io.Reader, *keys.SignPublicKey, error) {
	if s.armor {
		return s.NewVerifyArmoredStream(r)
	}
	spk, reader, err := ksaltpack.NewVerifyStream(versionValidator, r, s)
	if err != nil {
		return nil, nil, convertErr(err)
	}
	return reader, toSignPublicKey(spk), nil
}

// NewVerifyArmoredStream ...
func (s *Saltpack) NewVerifyArmoredStream(r io.Reader) (io.Reader, *keys.SignPublicKey, error) {
	spk, reader, _, err := ksaltpack.NewDearmor62VerifyStream(versionValidator, r, s)
	if err != nil {
		return nil, nil, convertErr(err)
	}
	return reader, toSignPublicKey(spk), nil
}

// stripBefore removes text before BEGIN.
func stripBefore(message string) string {
	n := strings.Index(message, "BEGIN")
	if n == 0 {
		return message
	}
	return message[n:]
}
