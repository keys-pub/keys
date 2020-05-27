package keyring

import (
	"bytes"
	"strings"
	"time"

	"github.com/keys-pub/keys/encoding"
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

	id := auth.ID()
	krid := reserved("auth-") + id

	logger.Debugf("Provisioning %s", id)
	item := NewItem(krid, mk[:], "", time.Now())
	if err := setItem(st, service, item, auth.Key()); err != nil {
		return "", err
	}
	return id, nil
}

func authDeprovision(st Store, service string, id string) (bool, error) {
	logger.Debugf("Deprovisioning %s", id)
	krid := reserved("auth-") + id
	ok, err := st.Delete(service, krid)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func authProvisionIDs(st Store, service string) ([]string, error) {
	krids, err := st.IDs(service, WithReservedPrefix("auth"))
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(krids))
	for _, krid := range krids {
		id := parseAuthID(krid)
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// authUnlock returns (identifier, master key) or ("", "", nil) if a matching auth
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
		krid := reserved("auth-") + id
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

func newAuthID() string {
	b := rand32()
	return encoding.MustEncode(b[:], encoding.Base62)
}

func parseAuthID(s string) string {
	if s == "#auth" {
		return authV1ID()
	}
	if !strings.HasPrefix(s, "#auth-") {
		return ""
	}
	return s[6:]
}

func authV1ID() string {
	b := bytes.Repeat([]byte{0x00}, 8)
	return encoding.MustEncode(b, encoding.Base62)
}
