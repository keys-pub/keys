package upgrade

import (
	"time"

	"github.com/keys-pub/keys/keyring"
)

func upgrade(st keyring.Store, serviceFrom string, serviceTo string, id string, key *[32]byte) error {
	b, err := st.Get(serviceFrom, id)
	if err != nil {
		return err
	}

	itemV1, err := decodeItemV1(b, key)
	if err != nil {
		return err
	}

	itemV2 := &itemV2{
		ID:        itemV1.ID,
		Type:      itemV1.Type,
		Data:      itemV1.SecretData(),
		CreatedAt: time.Now(),
	}

	out, err := marshalV2(itemV2, key)
	if err != nil {
		return err
	}

	if err := st.Set(serviceTo, itemV2.ID, out, itemV2.Type); err != nil {
		return err
	}

	if _, err := st.Delete(serviceFrom, id); err != nil {
		return err
	}

	return nil
}
