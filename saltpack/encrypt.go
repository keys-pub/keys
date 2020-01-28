package saltpack

import (
	"io"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

// Encrypt bytes to recipients.
// Sender can be nil, if you want it to be anonymous.
// https://saltpack.org/encryption-format-v2
func (s *Saltpack) Encrypt(b []byte, sender *keys.BoxKey, recipients ...keys.ID) ([]byte, error) {
	recs, err := s.boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	if s.armor {
		s, err := ksaltpack.EncryptArmor62Seal(ksaltpack.Version2(), b, sbk, recs, s.armorBrand)
		return []byte(s), err
	}
	return ksaltpack.Seal(ksaltpack.Version2(), b, sbk, recs)
}

// Decrypt ...
func (s *Saltpack) Decrypt(b []byte) ([]byte, keys.ID, error) {
	if s.armor {
		return s.decryptArmored(b)
	}
	info, out, err := ksaltpack.Open(encryptVersionValidator, b, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	sender := keys.ID("")
	if !info.SenderIsAnon {
		sender, err = bytesToID(info.SenderKey.ToKID(), keys.X25519Public)
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to decrypt")
		}
	}
	return out, sender, nil
}

func (s *Saltpack) decryptArmored(b []byte) ([]byte, keys.ID, error) {
	// TODO: Casting to string could be a performance issue
	info, out, _, err := ksaltpack.Dearmor62DecryptOpen(encryptVersionValidator, string(b), s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	sender := keys.ID("")
	if !info.SenderIsAnon {
		sender, err = bytesToID(info.SenderKey.ToKID(), keys.X25519Public)
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to decrypt")
		}
	}
	return out, sender, nil
}

// NewEncryptStream creates an encrypted io.WriteCloser.
// Sender can be nil, if you want it to be anonymous.
func (s *Saltpack) NewEncryptStream(w io.Writer, sender *keys.BoxKey, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := s.boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	if s.armor {
		return ksaltpack.NewEncryptArmor62Stream(ksaltpack.Version2(), w, sbk, recs, s.armorBrand)
	}
	return ksaltpack.NewEncryptStream(ksaltpack.Version2(), w, sbk, recs)
}

// NewDecryptStream ...
func (s *Saltpack) NewDecryptStream(r io.Reader) (io.Reader, keys.ID, error) {
	if s.armor {
		return s.newDecryptArmoredStream(r)
	}
	info, stream, err := ksaltpack.NewDecryptStream(encryptVersionValidator, r, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	sender := keys.ID("")
	if !info.SenderIsAnon {
		sender, err = bytesToID(info.SenderKey.ToKID(), keys.X25519Public)
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to decrypt")
		}
	}
	return stream, sender, nil
}

func (s *Saltpack) newDecryptArmoredStream(r io.Reader) (io.Reader, keys.ID, error) {
	// TODO: Specifying nil for resolver will panic if box keys not found
	info, stream, _, err := ksaltpack.NewDearmor62DecryptStream(encryptVersionValidator, r, s)
	if err != nil {
		return nil, "", convertErr(err)
	}
	sender := keys.ID("")
	if !info.SenderIsAnon {
		sender, err = bytesToID(info.SenderKey.ToKID(), keys.X25519Public)
		if err != nil {
			return nil, "", errors.Wrapf(err, "failed to decrypt")
		}
	}
	return stream, sender, nil
}
