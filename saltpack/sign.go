package saltpack

import (
	"io"
	"strings"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// Sign ...
func Sign(b []byte, key *keys.EdX25519Key) ([]byte, error) {
	return ksaltpack.Sign(ksaltpack.Version2(), b, newSignKey(key))
}

// SignArmored ...
func SignArmored(b []byte, key *keys.EdX25519Key) (string, error) {
	return ksaltpack.SignArmor62(ksaltpack.Version2(), b, newSignKey(key), "")
}

// SignDetached ...
func SignDetached(b []byte, key *keys.EdX25519Key) ([]byte, error) {
	return ksaltpack.SignDetached(ksaltpack.Version2(), b, newSignKey(key))
}

// SignArmoredDetached ...
func SignArmoredDetached(b []byte, key *keys.EdX25519Key) (string, error) {
	return ksaltpack.SignDetachedArmor62(ksaltpack.Version2(), b, newSignKey(key), "")
}

// Verify ...
func Verify(b []byte) ([]byte, keys.ID, error) {
	s := &saltpack{}
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
func VerifyArmored(msg string) ([]byte, keys.ID, error) {
	s := &saltpack{}
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
func VerifyDetached(sig []byte, b []byte) (keys.ID, error) {
	s := &saltpack{}
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
func VerifyArmoredDetached(sig string, b []byte) (keys.ID, error) {
	s := &saltpack{}
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
func NewSignStream(w io.Writer, key *keys.EdX25519Key) (io.WriteCloser, error) {
	return ksaltpack.NewSignStream(ksaltpack.Version1(), w, newSignKey(key))
}

// NewSignArmoredDetachedStream ...
func NewSignArmoredDetachedStream(w io.Writer, key *keys.EdX25519Key) (io.WriteCloser, error) {
	return ksaltpack.NewSignDetachedArmor62Stream(ksaltpack.Version1(), w, newSignKey(key), "")
}

// NewSignArmoredStream ...
func NewSignArmoredStream(w io.Writer, key *keys.EdX25519Key) (io.WriteCloser, error) {
	return ksaltpack.NewSignArmor62Stream(ksaltpack.Version1(), w, newSignKey(key), "")
}

// NewSignDetachedStream ...
func NewSignDetachedStream(w io.Writer, key *keys.EdX25519Key) (io.WriteCloser, error) {
	return ksaltpack.NewSignDetachedStream(ksaltpack.Version1(), w, newSignKey(key))
}

// NewVerifyStream ...
func NewVerifyStream(r io.Reader) (io.Reader, keys.ID, error) {
	s := &saltpack{}
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
func NewVerifyArmoredStream(r io.Reader) (io.Reader, keys.ID, error) {
	s := &saltpack{}
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

// VerifyDetachedReader ...
func VerifyDetachedReader(sig []byte, r io.Reader) (keys.ID, error) {
	s := &saltpack{}
	spk, err := ksaltpack.VerifyDetachedReader(signVersionValidator, r, sig, s)
	if err != nil {
		return "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return "", errors.Wrapf(err, "failed to verify")
	}
	return signer, nil
}

// VerifyArmoredDetachedReader ...
func VerifyArmoredDetachedReader(sig string, r io.Reader) (keys.ID, error) {
	s := &saltpack{}
	spk, _, err := ksaltpack.Dearmor62VerifyDetachedReader(signVersionValidator, r, sig, s)
	if err != nil {
		return "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return "", errors.Wrapf(err, "failed to verify")
	}
	return signer, nil
}

// StripBefore removes text before BEGIN.
func StripBefore(message string) string {
	n := strings.Index(message, "BEGIN")
	if n == 0 {
		return message
	}
	return message[n:]
}
