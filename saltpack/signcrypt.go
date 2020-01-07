package saltpack

import (
	"io"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

type ephemeralKeyCreator struct{}

func (c ephemeralKeyCreator) CreateEphemeralKey() (ksaltpack.BoxSecretKey, error) {
	boxKey := generateBoxKey()
	return boxKey, nil
}

func boxPublicKeys(recipients []keys.BoxPublicKey) ([]ksaltpack.BoxPublicKey, error) {
	publicKeys := make([]ksaltpack.BoxPublicKey, 0, len(recipients))
	for _, r := range recipients {
		if r == nil {
			return nil, errors.Errorf("nil recipient")
		}
		pk := newBoxPublicKey(r)
		publicKeys = append(publicKeys, pk)
	}
	return publicKeys, nil
}

// Signcrypt ...
func (s *Saltpack) Signcrypt(b []byte, sender *keys.SignKey, recipients ...keys.BoxPublicKey) ([]byte, error) {
	recs, err := boxPublicKeys(recipients)
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
func (s *Saltpack) SigncryptOpen(b []byte) ([]byte, *keys.SignPublicKey, error) {
	if s.armor {
		// if !keys.IsASCII(b) {
		// 	return nil, "", errors.Errorf("expecting armored input")
		// }
		return s.signcryptArmoredOpen(b)
	}
	sender, out, err := ksaltpack.SigncryptOpen(b, s, nil)
	if err != nil {
		return nil, nil, convertErr(err)
	}
	return out, toSignPublicKey(sender), nil
}

func (s *Saltpack) signcryptArmoredOpen(b []byte) ([]byte, *keys.SignPublicKey, error) {
	// TODO: Casting to string could be a performance issue
	sender, out, _, err := ksaltpack.Dearmor62SigncryptOpen(string(b), s, nil)
	if err != nil {
		return nil, nil, convertErr(err)
	}
	return out, toSignPublicKey(sender), nil
}

// NewSigncryptStream ...
func (s *Saltpack) NewSigncryptStream(w io.Writer, sender *keys.SignKey, recipients ...keys.BoxPublicKey) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	if s.armor {
		return ksaltpack.NewSigncryptArmor62SealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil, "")
	}
	return ksaltpack.NewSigncryptSealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil)
}

// NewSigncryptOpenStream ...
func (s *Saltpack) NewSigncryptOpenStream(r io.Reader) (io.Reader, *keys.SignPublicKey, error) {
	if s.armor {
		return s.newSigncryptArmoredOpenStream(r)
	}
	sender, stream, err := ksaltpack.NewSigncryptOpenStream(r, s, nil)
	if err != nil {
		return nil, nil, convertErr(err)
	}
	return stream, toSignPublicKey(sender), nil
}

func (s *Saltpack) newSigncryptArmoredOpenStream(r io.Reader) (io.Reader, *keys.SignPublicKey, error) {
	// TODO: Specifying nil for resolver will panic if box keys not found
	sender, stream, _, err := ksaltpack.NewDearmor62SigncryptOpenStream(r, s, nil)
	if err != nil {
		return nil, nil, convertErr(err)
	}
	return stream, toSignPublicKey(sender), nil
}
