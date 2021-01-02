package api

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Generic key brand.
const keyBrand = "KEY"

// EncodeKey a key with an optional password.
func EncodeKey(key *Key, password string) (string, error) {
	if key == nil {
		return "", errors.Errorf("no key to encode")
	}
	marshaled, err := msgpack.Marshal(key)
	if err != nil {
		return "", err
	}
	out := keys.EncryptWithPassword(marshaled, password)
	return encoding.EncodeSaltpack(out, keyBrand), nil
}

// DecodeKey a key with an optional password.
func DecodeKey(msg string, password string) (*Key, error) {
	decoded, brand, err := encoding.DecodeSaltpack(msg, false)
	if err != nil {
		return nil, errors.Errorf("failed to decode key")
	}
	b, err := keys.DecryptWithPassword(decoded, password)
	if err != nil {
		return nil, errors.Errorf("failed to decode key")
	}

	switch brand {
	case keyBrand:
		var key Key
		if err := msgpack.Unmarshal(b, &key); err != nil {
			return nil, errors.Errorf("failed to unmarshal key")
		}
		if err := key.Check(); err != nil {
			return nil, errors.Wrapf(err, "invalid key")
		}
		return &key, nil
	case edx25519Brand:
		if len(b) != 64 {
			return nil, errors.Errorf("invalid number of bytes for ed25519 seed")
		}
		sk := keys.NewEdX25519KeyFromPrivateKey(keys.Bytes64(b))
		return NewKey(sk), nil
	case x25519Brand:
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for x25519 private key")
		}
		bk := keys.NewX25519KeyFromPrivateKey(keys.Bytes32(b))
		return NewKey(bk), nil
	default:
		return nil, errors.Errorf("invalid key")
	}
}

// For EdX25519 key that only contains 64 private key bytes.
const edx25519Brand string = "EDX25519 KEY"

// For X25519 key that only contains 32 private key bytes.
const x25519Brand string = "X25519 KEY"
