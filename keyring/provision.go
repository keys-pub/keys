package keyring

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
)

func authSetup(st Store, service string, auth Auth) (string, SecretKey, error) {
	// MK is the master key.
	mk := rand32()
	id, err := authProvision(st, service, auth, mk)
	if err != nil {
		return "", nil, err
	}
	return id, mk, nil
}

func authProvision(st Store, service string, auth Auth, mk SecretKey) (string, error) {
	if mk == nil {
		return "", ErrLocked
	}

	id := reserved(fmt.Sprintf("auth-%s", randID()))

	logger.Debugf("Provisioning %s", id)
	item := NewItem(id, mk[:], "", time.Now())
	if err := setItem(st, service, item, auth.Key()); err != nil {
		return "", err
	}
	return id, nil
}

func authDeprovision(st Store, service string, id string) (bool, error) {
	logger.Debugf("Deprovisioning %s", id)
	ok, err := st.Delete(service, id)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func authProvisionIDs(st Store, service string) ([]string, error) {
	opts := &IDsOpts{
		Prefix:       reserved("auth"),
		ShowReserved: true,
	}
	ids, err := st.IDs(service, opts)
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// authUnlock returns (identifier, master key) or ("", nil) if a matching auth
// is not found.
func authUnlock(st Store, service string, auth Auth) (string, SecretKey, error) {
	if auth == nil {
		return "", nil, errors.Errorf("no auth specified")
	}

	ids, err := authProvisionIDs(st, service)
	if err != nil {
		return "", nil, err
	}

	for _, id := range ids {
		item, err := getItem(st, service, id, auth.Key())
		if err != nil {
			continue
		}
		if len(item.Data) != 32 {
			continue
		}
		if item != nil {
			return id, bytes32(item.Data), nil
		}
	}

	return "", nil, nil
}
