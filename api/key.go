// Package api provides a standard key format for serialization to JSON or
// msgpack, and conversions to and from specific key types.
package api

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/saltpack"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Key is a concrete type for the keys.Key interface, which can be serialized
// and converted to concrete key types like keys.EdX25519Key.
// It also includes additional fields and metadata.
type Key struct {
	ID   keys.ID `json:"id,omitempty" msgpack:"id,omitempty"`
	Type string  `json:"type,omitempty" msgpack:"type,omitempty"`

	Private []byte `json:"priv,omitempty" msgpack:"priv,omitempty"`
	Public  []byte `json:"pub,omitempty" msgpack:"pub,omitempty"`

	// Optional fields
	Notes string `json:"notes,omitempty" msgpack:"notes,omitempty"`

	CreatedAt int64 `json:"cts,omitempty" msgpack:"cts,omitempty"`
	UpdatedAt int64 `json:"uts,omitempty" msgpack:"uts,omitempty"`
}

// NewKey creates api.Key from keys.Key interface.
func NewKey(k keys.Key) *Key {
	return &Key{
		ID:      k.ID(),
		Public:  k.Public(),
		Private: k.Private(),
		Type:    string(k.Type()),
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

// DecryptKey decrypts a key from a sender.
func DecryptKey(b []byte, kr saltpack.Keyring) (*Key, *keys.EdX25519PublicKey, error) {
	dec, pk, err := saltpack.SigncryptOpen(b, true, kr)
	if err != nil {
		return nil, nil, err
	}
	var key Key
	if err := msgpack.Unmarshal(dec, &key); err != nil {
		return nil, nil, err
	}
	if err := key.Check(); err != nil {
		return nil, nil, err
	}
	return &key, pk, nil
}

// Check if key is valid (has valid ID and type).
func (k *Key) Check() error {
	if _, err := keys.ParseID(string(k.ID)); err != nil {
		return err
	}
	if k.Type == "" {
		return errors.Errorf("invalid key type")
	}
	return nil
}

// EncryptWithPassword creates an encrypted key using a password.
func (k *Key) EncryptWithPassword(password string) (string, error) {
	b, err := msgpack.Marshal(k)
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
	if err := key.Check(); err != nil {
		return nil, err
	}
	return &key, nil
}
