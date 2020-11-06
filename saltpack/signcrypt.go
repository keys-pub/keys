package saltpack

import (
	"io"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

// Signcrypt to recipients.
// https://saltpack.org/signcryption-format
func Signcrypt(b []byte, sender *keys.EdX25519Key, recipients ...keys.ID) ([]byte, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sk ksaltpack.SigningSecretKey
	if sender != nil {
		sk = newSignKey(sender)
	}
	return ksaltpack.SigncryptSeal(b, ephemeralKeyCreator{}, sk, recs, nil)
}

// SigncryptArmored signcrypts with armored output.
func SigncryptArmored(b []byte, brand string, sender *keys.EdX25519Key, recipients ...keys.ID) (string, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return "", err
	}
	var sk ksaltpack.SigningSecretKey
	if sender != nil {
		sk = newSignKey(sender)
	}
	s, err := ksaltpack.SigncryptArmor62Seal(b, ephemeralKeyCreator{}, sk, recs, nil, brand)
	if err != nil {
		return "", err
	}
	return s, nil
}

func edx25519SenderKey(senderPub ksaltpack.SigningPublicKey) (*keys.EdX25519PublicKey, error) {
	if senderPub == nil {
		return nil, nil
	}
	b := senderPub.ToKID()
	if len(b) != 32 {
		return nil, errors.Errorf("invalid edx25519 sender key")
	}
	return keys.NewEdX25519PublicKey(keys.Bytes32(b)), nil
}

// SigncryptOpen ...
func SigncryptOpen(b []byte, kr Keyring) ([]byte, *keys.EdX25519PublicKey, error) {
	sp := newSaltpack(kr)
	spk, out, err := ksaltpack.SigncryptOpen(b, sp, nil)
	if err != nil {
		return nil, nil, convertSignKeyErr(err)
	}
	sender, err := edx25519SenderKey(spk)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to signcrypt open")
	}
	return out, sender, nil
}

// SigncryptOpenArmored decrypts armored saltpack.
func SigncryptOpenArmored(s string, kr Keyring) ([]byte, *keys.EdX25519PublicKey, string, error) {
	sp := newSaltpack(kr)
	spk, out, brand, err := ksaltpack.Dearmor62SigncryptOpen(s, sp, nil)
	if err != nil {
		return nil, nil, "", convertSignKeyErr(err)
	}
	sender, err := edx25519SenderKey(spk)
	if err != nil {
		return nil, nil, "", errors.Wrapf(err, "failed to signcrypt open")
	}
	return out, sender, brand, nil
}

// NewSigncryptStream creates a signcrypt stream.
func NewSigncryptStream(w io.Writer, sender *keys.EdX25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	return ksaltpack.NewSigncryptSealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil)
}

// NewSigncryptArmoredStream creates an armored signcrypt stream.
func NewSigncryptArmoredStream(w io.Writer, brand string, sender *keys.EdX25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	return ksaltpack.NewSigncryptArmor62SealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil, brand)
}

// NewSigncryptOpenStream creates a signcrypt open stream.
func NewSigncryptOpenStream(r io.Reader, kr Keyring) (io.Reader, *keys.EdX25519PublicKey, error) {
	sp := newSaltpack(kr)
	spk, stream, err := ksaltpack.NewSigncryptOpenStream(r, sp, nil)
	if err != nil {
		return nil, nil, convertSignKeyErr(err)
	}
	sender, err := edx25519SenderKey(spk)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to signcrypt open")
	}
	return stream, sender, nil
}

// NewSigncryptOpenArmoredStream creates a signcrypt armored open stream.
func NewSigncryptOpenArmoredStream(r io.Reader, kr Keyring) (io.Reader, *keys.EdX25519PublicKey, string, error) {
	sp := newSaltpack(kr)
	spk, stream, brand, err := ksaltpack.NewDearmor62SigncryptOpenStream(r, sp, nil)
	if err != nil {
		return nil, nil, "", convertSignKeyErr(err)
	}
	sender, err := edx25519SenderKey(spk)
	if err != nil {
		return nil, nil, "", errors.Wrapf(err, "failed to signcrypt open")
	}
	return stream, sender, brand, nil
}

type ephemeralKeyCreator struct{}

func (c ephemeralKeyCreator) CreateEphemeralKey() (ksaltpack.BoxSecretKey, error) {
	boxKey := generateBoxKey()
	return boxKey, nil
}
