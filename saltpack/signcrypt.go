package saltpack

import (
	"io"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

// Signcrypt to recipients.
// https://saltpack.org/signcryption-format
func (s *Saltpack) Signcrypt(b []byte, sender *keys.EdX25519Key, recipients ...keys.ID) ([]byte, error) {
	recs, err := s.boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	if sender == nil {
		return nil, errors.Errorf("no sender specified")
	}
	sk := newSignKey(sender)
	return ksaltpack.SigncryptSeal(b, ephemeralKeyCreator{}, sk, recs, nil)
}

// SigncryptArmored to recipients.
func (s *Saltpack) SigncryptArmored(b []byte, sender *keys.EdX25519Key, recipients ...keys.ID) (string, error) {
	recs, err := s.boxPublicKeys(recipients)
	if err != nil {
		return "", err
	}
	if sender == nil {
		return "", errors.Errorf("no sender specified")
	}
	sk := newSignKey(sender)
	return ksaltpack.SigncryptArmor62Seal(b, ephemeralKeyCreator{}, sk, recs, nil, "")
}

func edx25519SenderKey(senderPub ksaltpack.SigningPublicKey) (*keys.EdX25519PublicKey, error) {
	if senderPub == nil {
		return nil, nil
	}
	b := senderPub.ToKID()
	if len(b) != 32 {
		return nil, errors.Errorf("invalid (edx25519) sender key")
	}
	return keys.NewEdX25519PublicKey(keys.Bytes32(b)), nil

}

// SigncryptOpen ...
func (s *Saltpack) SigncryptOpen(b []byte) ([]byte, *keys.EdX25519PublicKey, error) {
	spk, out, err := ksaltpack.SigncryptOpen(b, s, nil)
	if err != nil {
		return nil, nil, convertSignKeyErr(err)
	}
	sender, err := edx25519SenderKey(spk)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to signcrypt open")
	}
	return out, sender, nil
}

// SigncryptArmoredOpen ...
func (s *Saltpack) SigncryptArmoredOpen(str string) ([]byte, *keys.EdX25519PublicKey, error) {
	// TODO: Casting to string could be a performance issue
	spk, out, _, err := ksaltpack.Dearmor62SigncryptOpen(str, s, nil)
	if err != nil {
		return nil, nil, convertSignKeyErr(err)
	}
	sender, err := edx25519SenderKey(spk)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to signcrypt open")
	}
	return out, sender, nil
}

// NewSigncryptStream creates a signcrypt stream.
func (s *Saltpack) NewSigncryptStream(w io.Writer, sender *keys.EdX25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := s.boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	return ksaltpack.NewSigncryptSealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil)
}

// NewSigncryptArmoredStream creates a signcrypt stream.
func (s *Saltpack) NewSigncryptArmoredStream(w io.Writer, sender *keys.EdX25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := s.boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	return ksaltpack.NewSigncryptArmor62SealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil, "")
}

// NewSigncryptOpenStream creates a signcrypt open stream.
func (s *Saltpack) NewSigncryptOpenStream(r io.Reader) (io.Reader, *keys.EdX25519PublicKey, error) {
	spk, stream, err := ksaltpack.NewSigncryptOpenStream(r, s, nil)
	if err != nil {
		return nil, nil, convertSignKeyErr(err)
	}
	sender, err := edx25519SenderKey(spk)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to signcrypt open")
	}
	return stream, sender, nil
}

// NewSigncryptArmoredOpenStream ...
func (s *Saltpack) NewSigncryptArmoredOpenStream(r io.Reader) (io.Reader, *keys.EdX25519PublicKey, error) {
	// TODO: Specifying nil for resolver will panic if box keys not found
	spk, stream, _, err := ksaltpack.NewDearmor62SigncryptOpenStream(r, s, nil)
	if err != nil {
		return nil, nil, convertSignKeyErr(err)
	}
	sender, err := edx25519SenderKey(spk)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to signcrypt open")
	}
	return stream, sender, nil
}

type ephemeralKeyCreator struct{}

func (c ephemeralKeyCreator) CreateEphemeralKey() (ksaltpack.BoxSecretKey, error) {
	boxKey := generateBoxKey()
	return boxKey, nil
}
