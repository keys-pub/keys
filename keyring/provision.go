package keyring

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

func authSetup(st Store, service string, auth Auth) (provisionID, SecretKey, error) {
	// MK is the master key.
	mk := rand32()
	id, err := authProvision(st, service, auth, mk)
	if err != nil {
		return "", nil, err
	}
	return id, mk, nil
}

func authProvision(st Store, service string, auth Auth, mk SecretKey) (provisionID, error) {
	if mk == nil {
		return "", ErrLocked
	}

	id := newProvisionID()
	krid := reserved(fmt.Sprintf("auth-%s", id))

	logger.Debugf("Provisioning %s", id)
	item := NewItem(krid, mk[:], "", time.Now())
	if err := setItem(st, service, item, auth.Key()); err != nil {
		return "", err
	}
	return id, nil
}

func authDeprovision(st Store, service string, id provisionID) (bool, error) {
	logger.Debugf("Deprovisioning %s", id)
	krid := reserved(fmt.Sprintf("auth-%s", id))
	ok, err := st.Delete(service, krid)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func authProvisionIDs(st Store, service string) ([]provisionID, error) {
	krids, err := st.IDs(service, WithReservedPrefix("auth"))
	if err != nil {
		return nil, err
	}
	ids := make([]provisionID, 0, len(krids))
	for _, krid := range krids {
		pid := parseProvisionID(krid)
		if pid == "" {
			continue
		}
		ids = append(ids, pid)
	}
	return ids, nil
}

// authUnlock returns (identifier, master key) or ("", nil) if a matching auth
// is not found.
func authUnlock(st Store, service string, auth Auth) (provisionID, SecretKey, error) {
	if auth == nil {
		return "", nil, errors.Errorf("no auth specified")
	}

	ids, err := authProvisionIDs(st, service)
	if err != nil {
		return "", nil, err
	}

	for _, id := range ids {
		krid := id.keyringID()
		item, err := getItem(st, service, krid, auth.Key())
		if err != nil {
			continue
		}
		if item == nil {
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

// provisionID is an identifier for provisioned auth.
type provisionID string

func newProvisionID() provisionID {
	b := rand32()
	return provisionID(encoding.MustEncode(b[:], encoding.Base62))
}

func parseProvisionID(s string) provisionID {
	if s == "#auth" {
		return provisionV1ID()
	}
	if !strings.HasPrefix(s, "#auth-") {
		return ""
	}
	return provisionID(s[6:])
}

// provisionV1ID is the placeholder id for v1 #auth.
func provisionV1ID() provisionID {
	b := bytes.Repeat([]byte{0x00}, 8)
	return provisionID(encoding.MustEncode(b, encoding.Base62))
}

// keyringID returns keyring item identifier.
func (p provisionID) keyringID() string {
	return fmt.Sprintf("#auth-%s", p)
}
