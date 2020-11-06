package saltpack

import (
	"bytes"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
)

// Encoding for saltpack (armored vs binary, encrypt vs signcrypt).
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

// Detected encryption type.
type Detected struct {
	Encoding Encoding
	Armored  bool
	Brand    string
}

// TODO: Fix brand detection
func detectEncrypt(b []byte) Detected {
	if _, _, err := NewDecryptStream(bytes.NewReader(b), nil); err == ksaltpack.ErrNoDecryptionKey {
		return Detected{Encoding: EncryptEncoding}
	}
	if _, _, brand, err := NewDecryptArmoredStream(bytes.NewReader(b), nil); err == ksaltpack.ErrNoDecryptionKey {
		return Detected{Encoding: EncryptEncoding, Brand: brand, Armored: true}
	}
	if _, _, err := NewSigncryptOpenStream(bytes.NewReader(b), nil); err == ksaltpack.ErrNoDecryptionKey {
		return Detected{Encoding: SigncryptEncoding}
	}
	if _, _, brand, err := NewSigncryptOpenArmoredStream(bytes.NewReader(b), nil); err == ksaltpack.ErrNoDecryptionKey {
		return Detected{Encoding: SigncryptEncoding, Brand: brand, Armored: true}
	}
	return Detected{Encoding: UnknownEncoding}
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
