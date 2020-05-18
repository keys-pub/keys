package keyring

import (
	"crypto/subtle"

	"github.com/pkg/errors"
)

// Exported details.
type Exported struct {
	Add    []*Item
	Update []*Item
}

// Export items from a keyring to another keyring.
func Export(from *Keyring, to *Keyring) (*Exported, error) {
	items, err := from.List(nil)
	if err != nil {
		return nil, err
	}

	added := []*Item{}
	updated := []*Item{}

	for _, item := range items {
		existing, err := to.Get(item.ID)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			// Update
			chg, err := itemChanged(existing, item)
			if err != nil {
				return nil, err
			}
			if chg {
				updated = append(updated, item)
				if err := to.Update(item.ID, item.Data); err != nil {
					return nil, err
				}
			}
		} else {
			// Add
			if err := to.Create(item); err != nil {
				return nil, err
			}
			added = append(added, item)
		}
	}

	return &Exported{
		Add:    added,
		Update: updated,
	}, nil
}

func itemChanged(item1 *Item, item2 *Item) (bool, error) {
	if item1.ID != item2.ID {
		return false, errors.Errorf("mismatched item ids")
	}
	if item1.Type != item2.Type {
		return false, errors.Errorf("mismatched item types")
	}
	if subtle.ConstantTimeCompare(item1.Data, item2.Data) != 1 {
		return true, nil
	}
	return false, nil
}
