package keyring

import (
	"sort"
	"strings"

	"github.com/keybase/go-keychain"
	"github.com/pkg/errors"
)

type sys struct {
	service string
}

// System returns keyring store for darwin.
func system(service string) Store {
	return sys{
		service: service,
	}
}

func checkSystem() error {
	return nil
}

func (k sys) Name() string {
	return "keychain"
}

func (k sys) Get(id string) ([]byte, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(k.service)
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

func (k sys) Set(id string, data []byte) error {
	// Remove existing
	_, err := k.Delete(id)
	if err != nil {
		return errors.Wrapf(err, "failed to remove existing keychain item before add")
	}
	return add(k.service, id, data, "")
}

func (k sys) Delete(id string) (bool, error) {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(k.service)
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

func (k sys) Exists(id string) (bool, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(k.service)
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

func (k sys) Reset() error {
	return resetDefault(k)
}

func (k sys) IDs(opts ...IDsOption) ([]string, error) {
	options := NewIDsOptions(opts...)
	prefix, showHidden, showReserved := options.Prefix, options.Hidden, options.Reserved

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(k.service)
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
		if !showReserved && strings.HasPrefix(id, ReservedPrefix) {
			continue
		}
		if !showHidden && strings.HasPrefix(id, HiddenPrefix) {
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
