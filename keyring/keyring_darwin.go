package keyring

import (
	"sort"
	"strings"

	"github.com/keybase/go-keychain"
	"github.com/keys-pub/keys/docs"
	"github.com/pkg/errors"
)

type sys struct {
	service string
}

func newSystem(service string) Keyring {
	return sys{
		service: service,
	}
}

// CheckSystem returns error if system keychain/keyring/credentials api is not available.
func CheckSystem() error {
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
	return reset(k)
}

func (k sys) Documents(opt ...docs.Option) ([]*docs.Document, error) {
	opts := docs.NewOptions(opt...)

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
		return []*docs.Document{}, nil
	}

	out := make([]*docs.Document, 0, len(results))
	for _, r := range results {
		path := r.Account
		if opts.Prefix != "" && !strings.HasPrefix(path, opts.Prefix) {
			continue
		}
		doc := &docs.Document{Path: path}
		if !opts.NoData {
			// TODO: Iterator
			b, err := k.Get(path)
			if err != nil {
				return nil, err
			}
			doc.Data = b
		}
		out = append(out, doc)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out, nil
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
