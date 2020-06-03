package saltpack

import (
	"io"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

// Encrypt to recipients.
// Sender can be nil, if you want it to be anonymous.
// https://saltpack.org/encryption-format-v2
func Encrypt(b []byte, sender *keys.X25519Key, recipients ...keys.ID) ([]byte, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	return ksaltpack.Seal(ksaltpack.Version2(), b, sbk, recs)
}

// EncryptArmored to recipients.
// Sender can be nil, if you want it to be anonymous.
// https://saltpack.org/encryption-format-v2
func EncryptArmored(b []byte, sender *keys.X25519Key, recipients ...keys.ID) (string, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return "", err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	return ksaltpack.EncryptArmor62Seal(ksaltpack.Version2(), b, sbk, recs, "")
}

func x25519SenderKey(info *ksaltpack.MessageKeyInfo) (*keys.X25519PublicKey, error) {
	var sender *keys.X25519PublicKey
	if !info.SenderIsAnon {
		b := info.SenderKey.ToKID()
		if len(b) != 32 {
			return nil, errors.Errorf("invalid (x25519) sender key")
		}
		sender = keys.NewX25519PublicKey(keys.Bytes32(b))
	}
	return sender, nil
}

// Decrypt bytes (using the specified keys).
// If there was a sender, will return a X25519 key ID.
func Decrypt(b []byte, ks KeyStore) ([]byte, *keys.X25519PublicKey, error) {
	s := newSaltpack(ks)
	info, out, err := ksaltpack.Open(encryptVersionValidator, b, s)
	if err != nil {
		return nil, nil, convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, err
	}
	return out, sender, nil
}

// DecryptArmored text (using the specified keys).
// If there was a sender, will return a X25519 key ID.
func DecryptArmored(str string, ks KeyStore) ([]byte, *keys.X25519PublicKey, error) {
	s := newSaltpack(ks)
	// TODO: Casting to string could be a performance issue
	info, out, _, err := ksaltpack.Dearmor62DecryptOpen(encryptVersionValidator, str, s)
	if err != nil {
		return nil, nil, convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, err
	}
	return out, sender, nil
}

// NewEncryptStream creates an encrypted io.WriteCloser.
// Sender can be nil, if you want it to be anonymous.
func NewEncryptStream(w io.Writer, sender *keys.X25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	return ksaltpack.NewEncryptStream(ksaltpack.Version2(), w, sbk, recs)
}

// NewEncryptArmoredStream creates an encrypted armored io.WriteCloser.
// Sender can be nil, if you want it to be anonymous.
func NewEncryptArmoredStream(w io.Writer, sender *keys.X25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	return ksaltpack.NewEncryptArmor62Stream(ksaltpack.Version2(), w, sbk, recs, "")
}

// NewDecryptStream creates a decryption stream (using the specified keys).
// If there was a sender, will return a X25519 key ID.
func NewDecryptStream(r io.Reader, ks KeyStore) (io.Reader, *keys.X25519PublicKey, error) {
	s := newSaltpack(ks)
	info, stream, err := ksaltpack.NewDecryptStream(encryptVersionValidator, r, s)
	if err != nil {
		return nil, nil, convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, err
	}
	return stream, sender, nil
}

// NewDecryptArmoredStream creates a decryption stream (using the specified keys).
// If there was a sender, will return a X25519 key ID.
func NewDecryptArmoredStream(r io.Reader, ks KeyStore) (io.Reader, *keys.X25519PublicKey, error) {
	s := newSaltpack(ks)
	// TODO: Specifying nil for resolver will panic if box keys not found
	info, stream, _, err := ksaltpack.NewDearmor62DecryptStream(encryptVersionValidator, r, s)
	if err != nil {
		return nil, nil, convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, err
	}
	return stream, sender, nil
}
