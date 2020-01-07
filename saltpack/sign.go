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
func (s *Saltpack) Verify(b []byte) ([]byte, keys.ID, error) {
	if s.armor {
		return s.verifyArmored(string(b))
	}
	spk, out, err := ksaltpack.Verify(versionValidator, b, s)
	if err != nil {
		return nil, "", convertErr(err)
	}

	return out, signPublicKeyToID(spk), nil
}

func (s *Saltpack) verifyArmored(msg string) ([]byte, keys.ID, error) {
	spk, out, _, err := ksaltpack.Dearmor62Verify(versionValidator, msg, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	return out, signPublicKeyToID(spk), nil
}

func signPublicKeyToID(spk ksaltpack.SigningPublicKey) keys.ID {
	b := spk.ToKID()
	if len(b) != keys.SignPublicKeySize {
		logger.Errorf("invalid sign public key bytes")
		return ""
	}
	out := keys.NewSignPublicKey(keys.Bytes32(b))
	return out.ID()
}

// VerifyDetached ...
func (s *Saltpack) VerifyDetached(sig []byte, b []byte) (keys.ID, error) {
	if s.armor {
		// TODO: Implement
		return "", errors.Errorf("not implemented")
	}
	spk, err := ksaltpack.VerifyDetached(versionValidator, b, sig, s)
	if err != nil {
		return "", convertErr(err)
	}

	return signPublicKeyToID(spk), nil
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
func (s *Saltpack) NewVerifyStream(r io.Reader) (io.Reader, keys.ID, error) {
	if s.armor {
		return s.NewVerifyArmoredStream(r)
	}
	spk, reader, err := ksaltpack.NewVerifyStream(versionValidator, r, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	return reader, signPublicKeyToID(spk), nil
}

// NewVerifyArmoredStream ...
func (s *Saltpack) NewVerifyArmoredStream(r io.Reader) (io.Reader, keys.ID, error) {
	spk, reader, _, err := ksaltpack.NewDearmor62VerifyStream(versionValidator, r, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	return reader, signPublicKeyToID(spk), nil
}

// stripBefore removes text before BEGIN.
func stripBefore(message string) string {
	n := strings.Index(message, "BEGIN")
	if n == 0 {
		return message
	}
	return message[n:]
}
