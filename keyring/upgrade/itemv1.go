package upgrade

import (
	"encoding/json"

	"github.com/pkg/errors"
)

type itemV1 struct {
	ID      string
	Type    string
	secrets map[string]secret
}

type secret struct {
	Data []byte `json:"data"`
}

func (i *itemV1) Secret() *secret {
	return i.SecretFor("")
}

func (i *itemV1) SecretData() []byte {
	secret := i.SecretFor("")
	if secret == nil {
		return nil
	}
	return secret.Data
}

func (i *itemV1) SecretFor(name string) *secret {
	if i.secrets == nil {
		return nil
	}
	val, ok := i.secrets[name]
	if !ok {
		return nil
	}
	return &val
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

func decodeItemV1(b []byte, secretKey *[32]byte) (*itemV1, error) {
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
				return nil, errors.Errorf("invalid auth")
			}
			data = b
		}
	case itemEncodingNone:
		data = ie.Data
	default:
		return nil, errors.Errorf("invalid encoding")
	}

	var secrets map[string]secret
	if data != nil {
		if err := json.Unmarshal(data, &secrets); err != nil {
			return nil, errors.Wrapf(err, "keyring item data is invalid")
		}
	}

	item := &itemV1{
		ID:      ie.ID,
		secrets: secrets,
		Type:    ie.Type,
	}

	return item, nil
}
