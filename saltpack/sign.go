package saltpack

import (
	"io"
	"strings"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// Sign ...
func (s *Saltpack) Sign(b []byte, key *keys.EdX25519Key) ([]byte, error) {
	return ksaltpack.Sign(ksaltpack.Version1(), b, newSignKey(key))
}

// SignArmored ...
func (s *Saltpack) SignArmored(b []byte, brand string, key *keys.EdX25519Key) (string, error) {
	return ksaltpack.SignArmor62(ksaltpack.Version1(), b, newSignKey(key), brand)
}

// SignDetached ...
func (s *Saltpack) SignDetached(b []byte, key *keys.EdX25519Key) ([]byte, error) {
	return ksaltpack.SignDetached(ksaltpack.Version1(), b, newSignKey(key))
}

// SignArmoredDetached ...
func (s *Saltpack) SignArmoredDetached(b []byte, brand string, key *keys.EdX25519Key) (string, error) {
	return ksaltpack.SignDetachedArmor62(ksaltpack.Version1(), b, newSignKey(key), brand)
}

// Verify ...
func (s *Saltpack) Verify(b []byte) ([]byte, keys.ID, error) {
	spk, out, err := ksaltpack.Verify(signVersionValidator, b, s)
	if err != nil {
		return nil, "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return out, signer, nil
}

// VerifyArmored ...
func (s *Saltpack) VerifyArmored(msg string) ([]byte, keys.ID, error) {
	spk, out, _, err := ksaltpack.Dearmor62Verify(signVersionValidator, msg, s)
	if err != nil {
		return nil, "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return out, signer, nil
}

// VerifyDetached ...
func (s *Saltpack) VerifyDetached(sig []byte, b []byte) (keys.ID, error) {
	spk, err := ksaltpack.VerifyDetached(signVersionValidator, b, sig, s)
	if err != nil {
		return "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return "", errors.Wrapf(err, "failed to verify")
	}
	return signer, nil
}

// VerifyArmoredDetached ...
func (s *Saltpack) VerifyArmoredDetached(sig string, b []byte) (keys.ID, error) {
	spk, _, err := ksaltpack.Dearmor62VerifyDetached(signVersionValidator, b, sig, s)
	if err != nil {
		return "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return "", errors.Wrapf(err, "failed to verify")
	}
	return signer, nil
}

// NewSignStream ...
func (s *Saltpack) NewSignStream(w io.Writer, key *keys.EdX25519Key, detached bool) (io.WriteCloser, error) {
	return ksaltpack.NewSignStream(ksaltpack.Version1(), w, newSignKey(key))
}

// NewSignArmoredDetachedStream ...
func (s *Saltpack) NewSignArmoredDetachedStream(w io.Writer, brand string, key *keys.EdX25519Key, detached bool) (io.WriteCloser, error) {
	return ksaltpack.NewSignDetachedArmor62Stream(ksaltpack.Version1(), w, newSignKey(key), brand)
}

// NewSignArmoredStream ...
func (s *Saltpack) NewSignArmoredStream(w io.Writer, brand string, key *keys.EdX25519Key, detached bool) (io.WriteCloser, error) {
	return ksaltpack.NewSignArmor62Stream(ksaltpack.Version1(), w, newSignKey(key), brand)
}

// NewSignDetachedStream ...
func (s *Saltpack) NewSignDetachedStream(w io.Writer, key *keys.EdX25519Key, detached bool) (io.WriteCloser, error) {
	return ksaltpack.NewSignDetachedStream(ksaltpack.Version1(), w, newSignKey(key))
}

// NewVerifyStream ...
func (s *Saltpack) NewVerifyStream(r io.Reader) (io.Reader, keys.ID, error) {
	spk, reader, err := ksaltpack.NewVerifyStream(signVersionValidator, r, s)
	if err != nil {
		return nil, "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return reader, signer, nil
}

// NewVerifyArmoredStream ...
func (s *Saltpack) NewVerifyArmoredStream(r io.Reader) (io.Reader, keys.ID, error) {
	spk, reader, _, err := ksaltpack.NewDearmor62VerifyStream(signVersionValidator, r, s)
	if err != nil {
		return nil, "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return reader, signer, nil
}

// StripBefore removes text before BEGIN.
func StripBefore(message string) string {
	n := strings.Index(message, "BEGIN")
	if n == 0 {
		return message
	}
	return message[n:]
}
