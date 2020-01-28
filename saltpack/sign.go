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
	if s.armor {
		s, err := ksaltpack.SignArmor62(ksaltpack.Version1(), b, newSignKey(key), s.armorBrand)
		return []byte(s), err
	}
	return ksaltpack.Sign(ksaltpack.Version1(), b, newSignKey(key))
}

// SignDetached ...
func (s *Saltpack) SignDetached(b []byte, key *keys.EdX25519Key) ([]byte, error) {
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
	spk, out, err := ksaltpack.Verify(signVersionValidator, b, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	sender, err := bytesToID(spk.ToKID(), keys.EdX25519Public)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return out, sender, nil
}

func (s *Saltpack) verifyArmored(msg string) ([]byte, keys.ID, error) {
	spk, out, _, err := ksaltpack.Dearmor62Verify(signVersionValidator, msg, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	sender, err := bytesToID(spk.ToKID(), keys.EdX25519Public)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return out, sender, nil
}

func bytesToID(b []byte, typ keys.KeyType) (keys.ID, error) {
	if len(b) != 32 {
		return "", errors.Errorf("invalid bytes for id")
	}
	switch typ {
	case keys.EdX25519Public:
		spk := keys.NewEdX25519PublicKey(keys.Bytes32(b))
		return spk.ID(), nil
	case keys.X25519Public:
		bpk := keys.NewX25519PublicKey(keys.Bytes32(b))
		return bpk.ID(), nil
	default:
		return "", errors.Errorf("unknown key type for id")
	}
}

// VerifyDetached ...
func (s *Saltpack) VerifyDetached(sig []byte, b []byte) (keys.ID, error) {
	if s.armor {
		// TODO: Implement
		return "", errors.Errorf("not implemented")
	}
	spk, err := ksaltpack.VerifyDetached(signVersionValidator, b, sig, s)
	if err != nil {
		return "", convertErr(err)
	}

	sender, err := bytesToID(spk.ToKID(), keys.EdX25519Public)
	if err != nil {
		return "", errors.Wrapf(err, "failed to verify")
	}
	return sender, nil
}

// NewSignStream ...
func (s *Saltpack) NewSignStream(w io.Writer, key *keys.EdX25519Key, detached bool) (io.WriteCloser, error) {
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
	spk, reader, err := ksaltpack.NewVerifyStream(signVersionValidator, r, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	sender, err := bytesToID(spk.ToKID(), keys.EdX25519Public)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return reader, sender, nil
}

// NewVerifyArmoredStream ...
func (s *Saltpack) NewVerifyArmoredStream(r io.Reader) (io.Reader, keys.ID, error) {
	spk, reader, _, err := ksaltpack.NewDearmor62VerifyStream(signVersionValidator, r, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	sender, err := bytesToID(spk.ToKID(), keys.EdX25519Public)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return reader, sender, nil
}

// stripBefore removes text before BEGIN.
func stripBefore(message string) string {
	n := strings.Index(message, "BEGIN")
	if n == 0 {
		return message
	}
	return message[n:]
}
