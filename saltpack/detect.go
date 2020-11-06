package saltpack

import (
	"bytes"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
)

// Encoding for saltpack (encrypt, signcrypt, sign).
type Encoding string

const (
	// UnknownEncoding is unknown.
	UnknownEncoding Encoding = ""
	// EncryptEncoding used saltpack.Encrypt
	EncryptEncoding Encoding = "encrypt"
	// SigncryptEncoding used saltpack.Signcrypt
	SigncryptEncoding Encoding = "signcrypt"
	// SignEncoding used saltpack.Sign
	SignEncoding Encoding = "sign"
)

func detectEncrypt(b []byte) (Encoding, bool) {
	if _, _, err := NewDecryptStream(bytes.NewReader(b), false, nil); err == ksaltpack.ErrNoDecryptionKey {
		return EncryptEncoding, false
	}
	if _, _, err := NewDecryptStream(bytes.NewReader(b), true, nil); err == ksaltpack.ErrNoDecryptionKey {
		return EncryptEncoding, true
	}
	if _, _, err := NewSigncryptOpenStream(bytes.NewReader(b), false, nil); err == ksaltpack.ErrNoDecryptionKey {
		return SigncryptEncoding, false
	}
	if _, _, err := NewSigncryptOpenStream(bytes.NewReader(b), true, nil); err == ksaltpack.ErrNoDecryptionKey {
		return SigncryptEncoding, true
	}
	return UnknownEncoding, false
}

func detectSign(b []byte) (Encoding, bool) {
	kr := &saltpack{}
	if _, _, _, err := ksaltpack.NewDearmor62VerifyStream(signVersionValidator, bytes.NewReader(b), kr); err == nil {
		return SignEncoding, true
	}
	if _, _, err := ksaltpack.NewVerifyStream(signVersionValidator, bytes.NewReader(b), kr); err == nil {
		return SignEncoding, false
	}
	return UnknownEncoding, false
}

func detectSignDetached(b []byte) (Encoding, bool) {
	kr := &saltpack{}
	var buf bytes.Buffer
	if _, _, err := ksaltpack.Dearmor62VerifyDetachedReader(signVersionValidator, &buf, string(b), kr); err == keys.ErrVerifyFailed {
		return SignEncoding, true
	}
	if _, err := ksaltpack.VerifyDetachedReader(signVersionValidator, &buf, b, kr); err == keys.ErrVerifyFailed {
		return SignEncoding, false
	}
	return UnknownEncoding, false
}
