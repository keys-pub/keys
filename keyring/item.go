package keyring

import (
	"time"

	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Item is a keyring entry.
type Item struct {
	ID        string    `msgpack:"id"`
	Type      string    `msgpack:"typ"`
	Data      []byte    `msgpack:"dat"`
	CreatedAt time.Time `msgpack:"cts"`
}

// NewItem creates an Item.
func NewItem(id string, b []byte, typ string, createdAt time.Time) *Item {
	item := &Item{ID: id, Data: b, Type: typ, CreatedAt: createdAt}
	return item
}

// Marshal Item to bytes, encrypted with a secret key.
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

// DecryptItem returns Item from bytes.
func DecryptItem(b []byte, secretKey SecretKey) (*Item, error) {
	return decrypt(b, secretKey)
}

func decrypt(b []byte, secretKey SecretKey) (*Item, error) {
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
