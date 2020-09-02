package saltpack

import (
	"io"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

// Signcrypt to recipients.
// https://saltpack.org/signcryption-format
func Signcrypt(b []byte, armored bool, sender *keys.EdX25519Key, recipients ...keys.ID) ([]byte, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sk ksaltpack.SigningSecretKey
	if sender != nil {
		sk = newSignKey(sender)
	}
	if armored {
		s, err := ksaltpack.SigncryptArmor62Seal(b, ephemeralKeyCreator{}, sk, recs, nil, "")
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return ksaltpack.SigncryptSeal(b, ephemeralKeyCreator{}, sk, recs, nil)
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
func SigncryptOpen(b []byte, armored bool, kr Keyring) ([]byte, *keys.EdX25519PublicKey, error) {
	s := newSaltpack(kr)
	var spk ksaltpack.SigningPublicKey
	var out []byte
	var err error
	if armored {
		spk, out, _, err = ksaltpack.Dearmor62SigncryptOpen(string(b), s, nil)
	} else {
		spk, out, err = ksaltpack.SigncryptOpen(b, s, nil)
	}
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
func NewSigncryptStream(w io.Writer, armored bool, sender *keys.EdX25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	if armored {
		return ksaltpack.NewSigncryptArmor62SealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil, "")
	}
	return ksaltpack.NewSigncryptSealStream(w, ephemeralKeyCreator{}, newSignKey(sender), recs, nil)
}

// NewSigncryptOpenStream creates a signcrypt open stream.
func NewSigncryptOpenStream(r io.Reader, armored bool, kr Keyring) (io.Reader, *keys.EdX25519PublicKey, error) {
	s := newSaltpack(kr)

	var spk ksaltpack.SigningPublicKey
	var stream io.Reader
	var err error
	if armored {
		spk, stream, _, err = ksaltpack.NewDearmor62SigncryptOpenStream(r, s, nil)
	} else {
		spk, stream, err = ksaltpack.NewSigncryptOpenStream(r, s, nil)
	}
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
