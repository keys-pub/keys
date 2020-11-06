// Package api provides a standard key format for serialization to JSON or
// msgpack, and conversions to and from specific key types.
package api

import (
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/saltpack"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Key is a serializable format for keys.Key.
type Key struct {
	ID   keys.ID `json:"id" msgpack:"id,omitempty"`
	Data []byte  `json:"data" msgpack:"data,omitempty"`
	Type string  `json:"type" msgpack:"type,omitempty"`

	// Optional fields
	Notes string `json:"notes,omitempty" msgpack:"notes,omitempty"`

	CreatedAt time.Time `json:"createdAt,omitempty" msgpack:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty" msgpack:"updatedAt,omitempty"`
}

// NewKey from keys.Key interface.
func NewKey(k keys.Key) *Key {
	return &Key{
		ID:   k.ID(),
		Data: k.Bytes(),
		Type: string(k.Type()),
	}
}

// AsEdX25519 returns a *EdX25519Key.
func (k *Key) AsEdX25519() (*keys.EdX25519Key, error) {
	if k.Type != string(keys.EdX25519) {
		return nil, errors.Errorf("type %s != %s", k.Type, keys.EdX25519)
	}
	b := k.Data
	if len(b) != 64 {
		return nil, errors.Errorf("invalid number of bytes for ed25519 private key")
	}
	out := keys.NewEdX25519KeyFromPrivateKey(keys.Bytes64(b))
	if out.ID() != k.ID {
		return nil, errors.Errorf("key id mismatch")
	}
	return out, nil
}

// AsX25519 returns a X25519Key.
// If key is a EdX25519Key, it's converted to a X25519Key.
func (k *Key) AsX25519() (*keys.X25519Key, error) {
	switch k.Type {
	case string(keys.X25519):
		bk := keys.NewX25519KeyFromPrivateKey(keys.Bytes32(k.Data))
		return bk, nil
	case string(keys.EdX25519):
		sk, err := k.AsEdX25519()
		if err != nil {
			return nil, err
		}
		return sk.X25519Key(), nil
	default:
		return nil, errors.Errorf("type %s != %s (or %s)", k.Type, keys.X25519, keys.EdX25519)
	}
}

// AsEdX25519Public returns a *EdX25519PublicKey.
func (k *Key) AsEdX25519Public() (*keys.EdX25519PublicKey, error) {
	switch k.Type {
	case string(keys.EdX25519):
		sk, err := k.AsEdX25519()
		if err != nil {
			return nil, err
		}
		return sk.PublicKey(), nil
	case string(keys.EdX25519Public):
		b := k.Data
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for ed25519 public key")
		}
		out := keys.NewEdX25519PublicKey(keys.Bytes32(b))
		return out, nil
	default:
		return nil, errors.Errorf("type %s != %s (or %s)", k.Type, keys.EdX25519Public, keys.EdX25519)
	}
}

// AsX25519Public returns a X25519PublicKey.
func (k *Key) AsX25519Public() (*keys.X25519PublicKey, error) {
	switch k.Type {
	case string(keys.X25519):
		sk, err := k.AsX25519()
		if err != nil {
			return nil, err
		}
		return sk.PublicKey(), nil
	case string(keys.X25519Public):
		b := k.Data
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for x25519 public key")
		}
		out := keys.NewX25519PublicKey(keys.Bytes32(b))
		return out, nil
	default:
		return nil, errors.Errorf("type %s != %s (or %s)", k.Type, keys.X25519Public, keys.X25519)
	}
}

// EncryptKey creates encrypted key from a sender to a recipient.
func EncryptKey(key *Key, sender *keys.EdX25519Key, recipient keys.ID) ([]byte, error) {
	b, err := msgpack.Marshal(key)
	if err != nil {
		return nil, err
	}
	enc, err := saltpack.Signcrypt(b, true, sender, recipient, sender.ID())
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// DecryptKey decrypts a key and sender.
func DecryptKey(b []byte, kr saltpack.Keyring) (*Key, *keys.EdX25519PublicKey, error) {
	dec, pk, err := saltpack.SigncryptOpen(b, true, kr)
	if err != nil {
		return nil, nil, err
	}
	var key Key
	if err := msgpack.Unmarshal(dec, &key); err != nil {
		return nil, nil, err
	}
	if err := Check(&key); err != nil {
		return nil, nil, err
	}
	return &key, pk, nil
}

// Check if key is valid (has valid ID and type).
func Check(key *Key) error {
	if _, err := keys.ParseID(string(key.ID)); err != nil {
		return err
	}
	if key.Type == "" {
		return errors.Errorf("invalid key type")
	}
	return nil
}

// EncryptKeyWithPassword creates an encrypted key using a password.
func EncryptKeyWithPassword(key *Key, password string) (string, error) {
	b, err := msgpack.Marshal(key)
	if err != nil {
		return "", err
	}
	out := keys.EncryptWithPassword(b, password)
	return encoding.EncodeSaltpack(out, "KEY"), nil
}

// DecryptKeyWithPassword decrypts a key using a password.
func DecryptKeyWithPassword(s string, password string) (*Key, error) {
	decoded, brand, err := encoding.DecodeSaltpack(s, false)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse saltpack")
	}
	// Check if small format (from keys.EncodeSaltpackKey).
	switch brand {
	case string(keys.EdX25519Brand), string(keys.X25519Brand):
		k, err := keys.DecodeSaltpackKey(s, password, false)
		if err != nil {
			return nil, err
		}
		return NewKey(k), nil
	}
	decrypted, err := keys.DecryptWithPassword(decoded, password)
	if err != nil {
		return nil, err
	}
	var key Key
	if err := msgpack.Unmarshal(decrypted, &key); err != nil {
		return nil, err
	}
	if err := Check(&key); err != nil {
		return nil, err
	}
	return &key, nil
}
