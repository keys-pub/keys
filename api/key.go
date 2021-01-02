// Package api provides a standard key format for serialization to JSON or
// msgpack, and conversions to and from specific key types.
package api

import (
	"github.com/keys-pub/keys"
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

	CreatedAt int64 `json:"cts,omitempty" msgpack:"cts,omitempty"`
	UpdatedAt int64 `json:"uts,omitempty" msgpack:"uts,omitempty"`

	// Optional fields
	Labels []string `json:"labels,omitempty" msgpack:"labels,omitempty"`
	Notes  string   `json:"notes,omitempty" msgpack:"notes,omitempty"`

	// Application specific fields
	Token string `json:"token,omitempty" msgpack:"token,omitempty"`
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

// Created marks the key as created with the specified time.
func (k *Key) Created(ts int64) *Key {
	k.CreatedAt = ts
	k.UpdatedAt = ts
	return k
}

// Updated marks the key as created with the specified time.
func (k *Key) Updated(ts int64) *Key {
	k.UpdatedAt = ts
	return k
}

// WithLabel returns key with label added.
func (k *Key) WithLabel(label string) *Key {
	if k.HasLabel(label) {
		return k
	}
	k.Labels = append(k.Labels, label)
	return k
}

// HasLabel returns true if key has label.
func (k Key) HasLabel(label string) bool {
	for _, l := range k.Labels {
		if l == label {
			return true
		}
	}
	return false
}

// Copy creates a copy of the key.
func (k *Key) Copy() *Key {
	b, err := msgpack.Marshal(k)
	if err != nil {
		return nil
	}
	var out Key
	if err := msgpack.Unmarshal(b, &out); err != nil {
		return nil
	}
	return &out
}

// Check if key is valid (has valid ID and type).
func (k *Key) Check() error {
	if k.ID == "" {
		return errors.Errorf("empty id")
	}
	if _, err := keys.ParseID(string(k.ID)); err != nil {
		return err
	}
	if k.Type == "" {
		return errors.Errorf("empty type")
	}
	if len(k.Public) == 0 && len(k.Private) == 0 {
		return errors.Errorf("no key data")
	}
	return nil
}
