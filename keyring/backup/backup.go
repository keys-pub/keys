package backup

import (
	"crypto/subtle"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// Store for backups.
type Store interface {
	SaveItems(items []*keyring.Item, key keyring.SecretKey) error
	ListItems(key keyring.SecretKey) ([]*keyring.Item, error)
}

// Export saves backup to a directory, encrypted with password.
func Export(kr *keyring.Keyring, store Store, key keyring.SecretKey) error {
	items, err := kr.List(nil)
	if err != nil {
		return err
	}

	if err := store.SaveItems(items, key); err != nil {
		return err
	}

	return nil
}

// Import backup from store into the Keyring.
// TODO: Option: Dry run.
// TODO: Option: Continue on error.
func Import(kr *keyring.Keyring, store Store, key keyring.SecretKey) error {
	items, err := store.ListItems(key)
	if err != nil {
		return err
	}

	for _, item := range items {
		existing, err := kr.Get(item.ID)
		if err != nil {
			return err
		}
		if existing != nil {
			if subtle.ConstantTimeCompare(item.Data, existing.Data) != 1 {
				return errors.Errorf("item already exists with different data")
			}
			if item.Type != existing.Type {
				return errors.Errorf("item already exists with different type")
			}
			// It's ok if creation date is different.
			// if item.CreatedAt != existing.CreatedAt {
			// 	return errors.Errorf("item already exists with different creation date")
			// }
		} else {
			if err := kr.Create(item); err != nil {
				return err
			}
		}
	}

	return nil
}
