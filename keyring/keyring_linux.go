package keyring

import (
	"sort"
	"strings"

	"github.com/godbus/dbus"
	"github.com/pkg/errors"
	gokeyring "github.com/zalando/go-keyring"
	ss "github.com/zalando/go-keyring/secret_service"
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
	return &linux{kr}, nil
}

type linux struct {
	*keyring
}

// List items.
func (k *linux) List(opts *ListOpts) ([]*Item, error) {
	if opts == nil {
		opts = &ListOpts{}
	}
	if k.key == nil {
		return nil, ErrLocked
	}
	svc, err := ss.NewSecretService()
	if err != nil {
		return nil, err
	}
	return list(svc, k.service, k.key, opts)
}

// Reset removes all values.
func (k *linux) Reset() error {
	svc, err := ss.NewSecretService()
	if err != nil {
		return err
	}
	paths, err := objectPaths(svc, k.service)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := svc.Delete(p); err != nil {
			return err
		}
	}
	return k.Lock()
}

func objectPaths(svc *ss.SecretService, service string) ([]dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()
	search := map[string]string{
		"service": service,
	}

	logger.Debugf("Unlock %s", collection.Path())
	err := svc.Unlock(collection.Path())
	if err != nil {
		return nil, err
	}

	logger.Debugf("Search %s", service)
	return svc.SearchItems(collection, search)
}

func list(svc *ss.SecretService, service string, key SecretKey, opts *ListOpts) ([]*Item, error) {
	if opts == nil {
		opts = &ListOpts{}
	}
	paths, err := objectPaths(svc, service)
	if err != nil {
		return nil, err
	}

	session, err := svc.OpenSession()
	if err != nil {
		return nil, err
	}
	defer svc.Close(session)

	items := make([]*Item, 0, len(paths))
	for _, p := range paths {
		logger.Debugf("GetSecret %s", session.Path())
		secret, err := svc.GetSecret(p, session.Path())
		if err != nil {
			return nil, err
		}
		if secret == nil {
			continue
		}
		if !isItem(secret.Value) {
			continue
		}
		item, err := DecodeItem(secret.Value, key)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(item.ID, hiddenPrefix) || strings.HasPrefix(item.ID, reservedPrefix) {
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

// Get item from keyring.
func (k sys) get(service string, id string) ([]byte, error) {
	s, err := gokeyring.Get(service, id)
	if err != nil {
		if err == gokeyring.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return []byte(s), nil
}

// Set item in keyring.
func (k sys) set(service string, id string, data []byte, typ string) error {
	return gokeyring.Set(service, id, string(data))
}

func (k sys) remove(service string, id string) (bool, error) {
	if err := gokeyring.Delete(service, id); err != nil {
		if err == gokeyring.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (k sys) ids(service string, prefix string, showHidden bool, showReserved bool) ([]string, error) {
	svc, err := ss.NewSecretService()
	if err != nil {
		return nil, err
	}
	items, err := list(svc, service, nil, nil)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if !showReserved && strings.HasPrefix(item.ID, reservedPrefix) {
			continue
		}
		if !showHidden && strings.HasPrefix(item.ID, hiddenPrefix) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(item.ID, prefix) {
			continue
		}
		ids = append(ids, item.ID)
	}
	return ids, nil
}

func (k sys) exists(service string, id string) (bool, error) {
	s, err := gokeyring.Get(service, id)
	if err != nil {
		if err == gokeyring.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	return s != "", nil
}
