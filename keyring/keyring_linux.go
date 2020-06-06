package keyring

import (
	"os/exec"
	"sort"
	"strings"

	"github.com/godbus/dbus"
	gokeyring "github.com/keys-pub/secretservice"
	ss "github.com/keys-pub/secretservice/secret_service"
	"github.com/pkg/errors"
)

func system(service string) Store {
	return sys{service: service}
}

type sys struct {
	service string
}

func (k sys) Name() string {
	return "secret-service"
}

// CheckSystem returns error if system keyring (dbus+libsecret) is not available.
func CheckSystem() error {
	path, err := exec.LookPath("dbus-launch")
	if err != nil || path == "" {
		return errors.Errorf("no dbus")
	}

	if _, err := gokeyring.Get("keys.pub", "test-key"); err != nil {
		if err == gokeyring.ErrNotFound {
			return nil
		}
		return err
	}
	return nil
}

// Get item in keyring.
func (k sys) Get(id string) ([]byte, error) {
	s, err := gokeyring.Get(k.service, id)
	if err != nil {
		if err == gokeyring.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return []byte(s), nil
}

// Set item in keyring.
func (k sys) Set(id string, data []byte) error {
	return gokeyring.Set(k.service, id, string(data))
}

func (k sys) Delete(id string) (bool, error) {
	if err := gokeyring.Delete(k.service, id); err != nil {
		if err == gokeyring.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (k sys) Reset() error {
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
	return nil
}

func (k sys) IDs(opts ...IDsOption) ([]string, error) {
	options := NewIDsOptions(opts...)
	prefix, showReserved := options.Prefix, options.Reserved

	svc, err := ss.NewSecretService()
	if err != nil {
		return nil, err
	}
	ids, err := secretServiceList(svc, k.service)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !showReserved && strings.HasPrefix(id, ReservedPrefix) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(id, prefix) {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

func (k sys) Exists(id string) (bool, error) {
	s, err := gokeyring.Get(k.service, id)
	if err != nil {
		if err == gokeyring.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	return s != "", nil
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

func secretServiceList(svc *ss.SecretService, service string) ([]string, error) {
	paths, err := objectPaths(svc, service)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(paths))
	for _, p := range paths {
		label, err := svc.GetLabel(p)
		if err != nil {
			return nil, err
		}
		// The labels that are generated by the go-keyring are unfortunately:
		// Password for '{id}' on '{service}'
		// So we parse it.
		// TODO: Use libsecret directly.
		spl := strings.Split(label, "'")
		if len(spl) < 2 {
			continue
		}
		id := spl[1]
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
