package saltpack

import (
	"io"

	"github.com/keys-pub/keys"

	ksaltpack "github.com/keybase/saltpack"
)

// Signcrypt to recipients.
// https://saltpack.org/signcryption-format
func (s *Saltpack) Signcrypt(b []byte, sender *keys.SignKey, recipients ...keys.ID) ([]byte, error) {
	recs, err := s.boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	if s.armor {
		s, err := ksaltpack.SigncryptArmor62Seal(b, ephemeralKeyCreator{}, newSignKey(sender), recs, nil, s.armorBrand)
		return []byte(s), err
	}
	return ksaltpack.SigncryptSeal(b, ephemeralKeyCreator{}, newSignKey(sender), recs, nil)
}

// SigncryptOpen ...
func (s *Saltpack) SigncryptOpen(b []byte) ([]byte, keys.ID, error) {
	if s.armor {
		return s.signcryptArmoredOpen(b)
	}
	sender, out, err := ksaltpack.SigncryptOpen(b, s, nil)
	if err != nil {
		return nil, "", convertErr(err)
	}
	return out, bytesToID(sender.ToKID(), keys.SignKeyType), nil
}

func (s *Saltpack) signcryptArmoredOpen(b []byte) ([]byte, keys.ID, error) {
	// TODO: Casting to string could be a performance issue
	sender, out, _, err := ksaltpack.Dearmor62SigncryptOpen(string(b), s, nil)
	if err != nil {
		return nil, "", convertErr(err)
	}
	return out, bytesToID(sender.ToKID(), keys.SignKeyType), nil
}

// NewSigncryptStream ...
func (s *Saltpack) NewSigncryptStream(w io.Writer, sender *keys.SignKey, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := s.boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	if s.armor {
		return ksaltpack.NewSigncryptArmor62SealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil, "")
	}
	return ksaltpack.NewSigncryptSealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil)
}

// NewSigncryptOpenStream ...
func (s *Saltpack) NewSigncryptOpenStream(r io.Reader) (io.Reader, keys.ID, error) {
	if s.armor {
		return s.newSigncryptArmoredOpenStream(r)
	}
	sender, stream, err := ksaltpack.NewSigncryptOpenStream(r, s, nil)
	if err != nil {
		return nil, "", convertErr(err)
	}
	return stream, bytesToID(sender.ToKID(), keys.SignKeyType), nil
}

func (s *Saltpack) newSigncryptArmoredOpenStream(r io.Reader) (io.Reader, keys.ID, error) {
	// TODO: Specifying nil for resolver will panic if box keys not found
	sender, stream, _, err := ksaltpack.NewDearmor62SigncryptOpenStream(r, s, nil)
	if err != nil {
		return nil, "", convertErr(err)
	}
	return stream, bytesToID(sender.ToKID(), keys.SignKeyType), nil
}

type ephemeralKeyCreator struct{}

func (c ephemeralKeyCreator) CreateEphemeralKey() (ksaltpack.BoxSecretKey, error) {
	boxKey := generateBoxKey()
	return boxKey, nil
}
