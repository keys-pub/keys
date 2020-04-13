package keyring

import (
	"time"

	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack"
)

// Item is a keyring entry.
type Item struct {
	ID        string
	Type      string
	Data      []byte
	CreatedAt time.Time
}

// NewItem creates an Item with a secret.
func NewItem(id string, b []byte, typ string, createdAt time.Time) *Item {
	item := &Item{ID: id, Data: b, Type: typ, CreatedAt: createdAt}
	return item
}

// Marshal to bytes.
// If secretKey is specified we store the data encrypted.
func (i *Item) Marshal(secretKey SecretKey) ([]byte, error) {
	if secretKey == nil {
		return nil, errors.Errorf("no secret key specified")
	}
	b, err := msgpack.Marshal(i)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal kerying item")
	}
	encrypted := secretBoxSeal(b, secretKey)
	return encrypted, nil
}

// DecodeItem returns Item from bytes.
// If encrypted and secret key is specified, it will have the decrypted data
// and will return (*Item, true, nil).
func DecodeItem(b []byte, secretKey SecretKey) (*Item, error) {
	return unmarshal(b, secretKey)
}

func unmarshal(b []byte, secretKey SecretKey) (*Item, error) {
	decrypted, ok := secretBoxOpen(b, secretKey)
	if !ok {
		return nil, ErrInvalidAuth
	}

	if decrypted == nil {
		return nil, errors.Errorf("no data")
	}
	var item Item
	if err := msgpack.Unmarshal(decrypted, &item); err != nil {
		return nil, errors.Wrapf(err, "keyring item data is invalid")
	}

	return &item, nil
}
