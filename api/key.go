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
// and converted to specific key types like keys.EdX25519Key.
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

// AsEdX25519 returns a *EdX25519Key.
// Returns nil if we can't resolve.
func (k *Key) AsEdX25519() *keys.EdX25519Key {
	if k.Type != string(keys.EdX25519) {
		return nil
	}
	if k.Private == nil {
		return nil
	}
	b := k.Private
	if len(b) != 64 {
		return nil
	}
	out := keys.NewEdX25519KeyFromPrivateKey(keys.Bytes64(b))
	if out.ID() != k.ID {
		return nil
	}
	return out
}

// AsX25519 returns a X25519Key.
// If key is a EdX25519Key, it's converted to a X25519Key.
// Returns nil if we can't resolve.
func (k *Key) AsX25519() *keys.X25519Key {
	if k.Private == nil {
		return nil
	}
	switch k.Type {
	case string(keys.X25519):
		bk := keys.NewX25519KeyFromPrivateKey(keys.Bytes32(k.Private))
		return bk
	case string(keys.EdX25519):
		sk := k.AsEdX25519()
		if sk == nil {
			return nil
		}
		return sk.X25519Key()
	default:
		return nil
	}
}

// AsEdX25519Public returns a *EdX25519PublicKey.
// Returns nil if we can't resolve.
func (k *Key) AsEdX25519Public() *keys.EdX25519PublicKey {
	if k.Type != string(keys.EdX25519) {
		return nil
	}

	if k.Private == nil {
		b := k.Public
		if len(b) != 32 {
			return nil
		}
		out := keys.NewEdX25519PublicKey(keys.Bytes32(b))
		return out
	}

	sk := k.AsEdX25519()
	if sk == nil {
		return nil
	}
	return sk.PublicKey()
}

// AsX25519Public returns a X25519PublicKey.
// Returns nil if we can't resolve.
func (k *Key) AsX25519Public() *keys.X25519PublicKey {
	if k.Type != string(keys.X25519) {
		return nil
	}

	if k.Private == nil {
		b := k.Public
		if len(b) != 32 {
			return nil
		}
		out := keys.NewX25519PublicKey(keys.Bytes32(b))
		return out
	}

	sk := k.AsX25519()
	if sk == nil {
		return nil
	}
	return sk.PublicKey()
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

// AsRSA returns a RSAKey.
// Returns nil if we can't resolve.
func (k *Key) AsRSA() *keys.RSAKey {
	if k.Private == nil {
		return nil
	}
	if k.Type != string(keys.RSA) {
		return nil
	}
	bk, err := keys.NewRSAKeyFromPrivateKey(k.Private)
	if err != nil {
		return nil
	}
	return bk
}
