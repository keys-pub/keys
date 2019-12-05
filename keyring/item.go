package keyring

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// Item is a keyring entry.
type Item struct {
	ID      string
	Type    string
	secrets map[string]Secret
}

// NewItem creates an Item with a secret.
func NewItem(id string, secret Secret, typ string) *Item {
	item := &Item{ID: id, Type: typ}
	item.SetSecret(secret)
	return item
}

// Secret for item.
type Secret struct {
	Data []byte `json:"data"`
}

// NewSecret returns a new secret with data.
func NewSecret(b []byte) Secret {
	return Secret{Data: b}
}

// String returns secret data as a string.
func (s *Secret) String() string {
	if s == nil {
		return ""
	}
	if len(s.Data) == 0 {
		return ""
	}
	return string(s.Data)
}

// NewStringSecret returns a new secret for a string.
func NewStringSecret(s string) Secret {
	return Secret{Data: []byte(s)}
}

// Secret ...
func (i *Item) Secret() *Secret {
	return i.SecretFor("")
}

// SecretData ...
func (i *Item) SecretData() []byte {
	secret := i.SecretFor("")
	if secret == nil {
		return nil
	}
	return secret.Data
}

// SecretFor returns a named secret.
func (i *Item) SecretFor(name string) *Secret {
	if i.secrets == nil {
		return nil
	}
	val, ok := i.secrets[name]
	if !ok {
		return nil
	}
	return &val
}

// SecretDataFor ...
func (i *Item) SecretDataFor(name string) []byte {
	secret := i.SecretFor(name)
	if secret == nil {
		return nil
	}
	return secret.Data
}

// SetSecret sets the secret.
func (i *Item) SetSecret(val Secret) {
	i.SetSecretFor("", val)
}

// SetSecretFor sets a named secret.
func (i *Item) SetSecretFor(name string, val Secret) {
	if i.secrets == nil {
		i.secrets = map[string]Secret{}
	}
	i.secrets[name] = val
}

type itemExport struct {
	ID       string       `json:"id"`
	Data     []byte       `json:"data"`
	Type     string       `json:"type"`
	Encoding itemEncoding `json:"enc"`
}

type itemEncoding string

const (
	itemEncodingNone itemEncoding = ""
	itemEncodingSeal itemEncoding = "sb"
)

// isItem returns true if bytes are an encoded item.
func isItem(b []byte) bool {
	var ie itemExport
	if err := json.Unmarshal(b, &ie); err != nil {
		return false
	}
	if ie.ID == "" {
		return false
	}
	return true
}

// Marshal to bytes.
// If secretKey is specified we store the data encrypted.
func (i *Item) Marshal(secretKey SecretKey) ([]byte, error) {
	if secretKey == nil {
		return nil, errors.Errorf("no secret key specified")
	}
	b, err := json.Marshal(i.secrets)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal kerying item")
	}

	ie := &itemExport{
		ID:       i.ID,
		Type:     i.Type,
		Data:     secretBoxSeal(b, secretKey),
		Encoding: itemEncodingSeal,
	}
	mb, err := json.Marshal(ie)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal kerying item")
	}
	return mb, nil
}

// DecodeItem returns Item from bytes.
// If encrypted and secret key is specified, it will have the decrypted data
// and will return (*Item, true, nil).
func DecodeItem(b []byte, secretKey SecretKey) (*Item, error) {
	return unmarshal(b, secretKey)
}

func unmarshal(b []byte, secretKey SecretKey) (*Item, error) {
	var ie itemExport
	if err := json.Unmarshal(b, &ie); err != nil {
		return nil, err
	}

	var data []byte
	switch ie.Encoding {
	case itemEncodingSeal:
		if secretKey != nil {
			b, ok := secretBoxOpen(ie.Data, secretKey)
			if !ok {
				return nil, ErrInvalidAuth
			}
			data = b
		}
	case itemEncodingNone:
		data = ie.Data
	default:
		return nil, errors.Errorf("invalid encoding")
	}

	var secrets map[string]Secret
	if data != nil {
		if err := json.Unmarshal(data, &secrets); err != nil {
			return nil, errors.Wrapf(err, "keyring item data is invalid")
		}
	}

	item := &Item{
		ID:      ie.ID,
		secrets: secrets,
		Type:    ie.Type,
	}

	return item, nil
}
