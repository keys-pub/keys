package keys

import (
	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

// Brand is saltpack brand.
type Brand string

// EdX25519Brand is saltpack brand for EdX25519 key.
const EdX25519Brand Brand = "EDX25519 KEY"

// X25519Brand is saltpack brand for X25519 key.
const X25519Brand Brand = "X25519 KEY"

// EncodeKeyToSaltpack encrypts a key to saltpack with password.
func EncodeKeyToSaltpack(key Key, password string) (string, error) {
	if key == nil {
		return "", errors.Errorf("no key to encode")
	}
	var brand Brand
	b := key.Bytes()
	switch key.Type() {
	case EdX25519:
		brand = EdX25519Brand
	case X25519:
		brand = X25519Brand
	default:
		return "", errors.Errorf("unsupported key type %s", key.Type())
	}
	out := EncryptWithPassword(b, password)
	return encoding.EncodeSaltpack(out, string(brand)), nil
}

// DecodeKeyFromSaltpack decrypts a saltpack encrypted key.
func DecodeKeyFromSaltpack(msg string, password string, isHTML bool) (Key, error) {
	encrypted, brand, err := encoding.DecodeSaltpack(msg, isHTML)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse saltpack")
	}
	b, err := DecryptWithPassword(encrypted, password)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decrypt saltpack encoded key")
	}
	if brand == "" {
		return nil, errors.Errorf("unable to determine key type from saltpack brand")
	}
	switch brand {
	case string(EdX25519Brand):
		if len(b) != 64 {
			return nil, errors.Errorf("invalid number of bytes for ed25519 seed")
		}
		sk := NewEdX25519KeyFromPrivateKey(Bytes64(b))
		return sk, nil
	case string(X25519Brand):
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for x25519 private key")
		}
		bk := NewX25519KeyFromPrivateKey(Bytes32(b))
		return bk, nil
	default:
		return nil, errors.Errorf("unknown key type %s", brand)
	}
}
