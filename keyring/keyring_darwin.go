package keyring

import (
	"sort"
	"strings"

	"github.com/keybase/go-keychain"
	"github.com/pkg/errors"
)

// NewKeyring ...
func NewKeyring(service string) (Keyring, error) {
	if service == "" {
		return nil, errors.Errorf("no service specified")
	}
	kr, err := newKeyring(system, service)
	if err != nil {
		return nil, err
	}
	return &darwin{kr}, nil
}

type darwin struct {
	*keyring
}

// List items.
func (k *darwin) List(opts *ListOpts) ([]*Item, error) {
	if opts == nil {
		opts = &ListOpts{}
	}
	if k.key == nil {
		return nil, ErrLocked
	}
	listQuery := keychain.NewItem()
	listQuery.SetSecClass(keychain.SecClassGenericPassword)
	listQuery.SetService(k.service)
	// if k.skc != nil {
	// 	query.SetMatchSearchList(*k.skc)
	// }

	listQuery.SetMatchLimit(keychain.MatchLimitAll)
	// listQuery.SetReturnData(true)
	listQuery.SetReturnAttributes(true)
	results, err := keychain.QueryItem(listQuery)
	if err != nil {
		return nil, err
	} else if len(results) == 0 {
		return []*Item{}, nil
	}

	items := make([]*Item, 0, len(results))
	for _, r := range results {
		if strings.HasPrefix(r.Account, hiddenPrefix) || strings.HasPrefix(r.Account, reservedPrefix) {
			continue
		}
		item, err := getItem(system, k.service, r.Account, k.key)
		if err != nil {
			return nil, err
		}
		if item == nil {
			continue
		}
		if len(opts.Types) != 0 && !contains(opts.Types, item.Type) {
			continue
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})

	return items, nil
}

var system = sys{}

type sys struct{}

func (k sys) get(service string, id string) ([]byte, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(id)
	// if k.skc != nil {
	// 	query.SetMatchSearchList(*k.skc)
	// }

	// query.SetAccessGroup(accessGroup)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, err
	} else if len(results) != 1 {
		return nil, nil
	}
	return results[0].Data, nil
}

func (k sys) set(service string, id string, data []byte, typ string) error {
	// Remove existing
	_, err := system.remove(service, id)
	if err != nil {
		return errors.Wrapf(err, "failed to remove existing keychain item before add")
	}
	return add(service, id, data, typ)
}

func (k sys) remove(service string, id string) (bool, error) {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(id)
	// if k.skc != nil {
	// 	item.SetMatchSearchList(*k.skc)
	// }

	err := keychain.DeleteItem(item)
	if err == keychain.ErrorItemNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (k sys) exists(service string, id string) (bool, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(id)
	query.SetMatchLimit(keychain.MatchLimitAll)
	// Do not return data.
	// query.SetReturnData(true)
	query.SetReturnAttributes(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return false, err
	} else if len(results) == 0 {
		return false, nil
	}
	return true, nil
}

func (k sys) ids(service string, prefix string, showHidden bool, showReserved bool) ([]string, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(service)
	// if k.skc != nil {
	// 	query.SetMatchSearchList(*k.skc)
	// }
	query.SetMatchLimit(keychain.MatchLimitAll)
	// Do not return data.
	// query.SetReturnData(true)
	query.SetReturnAttributes(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, err
	} else if len(results) == 0 {
		return []string{}, nil
	}

	ids := make([]string, 0, len(results))
	for _, r := range results {
		id := r.Account
		if !showReserved && strings.HasPrefix(id, reservedPrefix) {
			continue
		}
		if !showHidden && strings.HasPrefix(id, hiddenPrefix) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(id, prefix) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func newPasswordItem(service string, id string, data []byte, desc string) keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(id)
	item.SetData(data)
	item.SetDescription(desc)
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	// if k.skc != nil {
	// 	item.UseKeychain(*k.skc)
	// }
	// item.SetAccessGroup("A123456789.group.com.mycorp")
	return item
}

// add to keychain.
func add(service string, id string, data []byte, desc string) error {
	if id == "" {
		return errors.Errorf("no id")
	}
	if len(data) == 0 {
		return errors.Errorf("no data")
	}
	item := newPasswordItem(service, id, data, desc)
	return keychain.AddItem(item)
}
