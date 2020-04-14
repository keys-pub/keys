// +build windows darwin

package upgrade

import (
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// KeyringV1 upgrades keyring v1.
func KeyringV1(serviceFrom string, serviceTo string, password string) {
	sys := keyring.System()

	keyFrom, err := key(sys, serviceFrom, password)
	if err != nil {
		logger.Errorf("Failed to get source key: %s", err)
		return
	}
	if keyFrom == nil {
		logger.Infof("No source key for upgrade")
		return
	}
	keyTo, err := key(sys, serviceTo, password)
	if err != nil {
		logger.Errorf("Failed to get dest key: %s", err)
		return
	}
	if keyTo == nil {
		logger.Infof("No dest key for upgrade")
		return
	}
	keyringV1(sys, serviceFrom, keyFrom, serviceTo, keyTo)
}

func key(st keyring.Store, service string, password string) (*[32]byte, error) {
	salt, err := st.Get(service, "#salt")
	if err != nil {
		return nil, err
	}
	if salt == nil {
		return nil, nil
	}

	auth, err := keyring.NewPasswordAuth(password, salt)
	if err != nil {
		return nil, err
	}
	key := auth.Key()
	return key, nil
}

func upgrade(st keyring.Store, serviceFrom string, keyFrom *[32]byte, id string, serviceTo string, keyTo *[32]byte) error {
	existing, err := st.Get(serviceTo, id)
	if err != nil {
		return err
	}
	if existing != nil {
		if _, err := st.Delete(serviceFrom, id); err != nil {
			return err
		}
		return errors.Errorf("already exists at destination")
	}

	b, err := st.Get(serviceFrom, id)
	if err != nil {
		return err
	}

	itemV1, err := decodeItemV1(b, keyFrom)
	if err != nil {
		return err
	}

	itemV2 := &itemV2{
		ID:        itemV1.ID,
		Type:      itemV1.Type,
		Data:      itemV1.SecretData(),
		CreatedAt: time.Now(),
	}

	out, err := marshalV2(itemV2, keyTo)
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
