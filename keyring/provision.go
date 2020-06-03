package keyring

import (
	"sort"
	"strings"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// AuthType describes an auth method.
type AuthType string

const (
	// UnknownAuth ...
	UnknownAuth AuthType = ""
	// PasswordAuth ...
	PasswordAuth AuthType = "password"
	// FIDO2HMACSecretAuth ...
	FIDO2HMACSecretAuth AuthType = "fido2-hmac-secret" // #nosec
)

var provisionPrefix = reserved("provision-")

// Provision is unencrypted provision and parameters used by client auth.
type Provision struct {
	ID        string    `msgpack:"id"`
	Type      AuthType  `msgpack:"type"`
	CreatedAt time.Time `msgpack:"cts"`

	// For FIDO2HMACSecret

	AAGUID string `msgpack:"aaguid"`
	Salt   []byte `msgpack:"salt"`
	NoPin  bool   `msgpack:"nopin"`
}

// NewProvision creates a new provision.
func NewProvision(typ AuthType) *Provision {
	return &Provision{
		ID:        newProvisionID(),
		Type:      typ,
		CreatedAt: time.Now(),
	}
}

// Setup auth, if no auth exists.
// Returns ErrAlreadySetup if already setup.
// Doesn't require Unlock().
func (k *Keyring) Setup(key SecretKey, provision *Provision) error {
	status, err := k.Status()
	if err != nil {
		return err
	}
	if status != Setup {
		return ErrAlreadySetup
	}
	if provision == nil {
		return errors.Errorf("no provision")
	}
	mk, err := authSetup(k.st, provision.ID, key)
	if err != nil {
		return err
	}

	if provision != nil {
		if err := k.saveProvision(provision); err != nil {
			return err
		}
	}

	k.masterKey = mk
	return nil
}

// Provision new auth.
// Requires Unlock().
func (k *Keyring) Provision(key SecretKey, provision *Provision) error {
	if k.masterKey == nil {
		return ErrLocked
	}
	if provision == nil {
		return errors.Errorf("no provision")
	}

	if err := authCreate(k.st, provision.ID, key, k.masterKey); err != nil {
		return err
	}

	if provision != nil {
		if err := k.saveProvision(provision); err != nil {
			return err
		}
	}

	return nil
}

// Provisions are currently provisioned auth.
// Doesn't require Unlock().
func (k *Keyring) Provisions() ([]*Provision, error) {
	ids, err := provisionIDs(k.st)
	if err != nil {
		return nil, err
	}
	provisions := make([]*Provision, 0, len(ids))
	for _, id := range ids {
		provision, err := k.loadProvision(id)
		if err != nil {
			return nil, err
		}
		if provision == nil {
			provision = &Provision{
				ID: id,
			}
		}
		provisions = append(provisions, provision)
	}

	// Check for v1 auth
	v1, err := k.Store().Exists("#auth")
	if err != nil {
		return nil, err
	}
	if v1 {
		provisions = append(provisions, &Provision{ID: authV1ID})
	}

	// Sort by time
	sort.Slice(provisions, func(i, j int) bool { return provisions[i].CreatedAt.Before(provisions[j].CreatedAt) })

	return provisions, nil
}

// Deprovision auth.
// Doesn't require Unlock().
func (k *Keyring) Deprovision(id string, force bool) (bool, error) {
	ids, err := authIDs(k.Store())
	if err != nil {
		return false, err
	}
	if !force && len(ids) == 1 && id == ids[0] {
		return false, errors.Errorf("deprovisioning the last auth is not supported")
	}

	ok, err := authDelete(k.st, id)
	if err != nil {
		return false, err
	}
	_, err = k.deleteProvision(id)
	return ok, err
}

// SaveProvision for auth methods that need to store registration data before
// key is available (for example, FIDO2 hmac-secret).
func (k *Keyring) SaveProvision(provision *Provision) error {
	return k.saveProvision(provision)
}

func authSetup(st Store, id string, key SecretKey) (SecretKey, error) {
	// MK is the master key.
	mk := rand32()
	if err := authCreate(st, id, key, mk); err != nil {
		return nil, err
	}
	return mk, nil
}

func authCreate(st Store, id string, key SecretKey, mk SecretKey) error {
	if mk == nil {
		return ErrLocked
	}
	if id == "" {
		return errors.Errorf("no provision id")
	}
	krid := reserved("auth-") + id

	logger.Debugf("Provisioning %s", id)
	item := NewItem(krid, mk[:], "", time.Now())
	if err := setItem(st, item, key); err != nil {
		return err
	}
	return nil
}

func authDelete(st Store, id string) (bool, error) {
	if id == "" {
		return false, errors.Errorf("no provision id")
	}
	logger.Debugf("Deprovisioning %s", id)
	krid := reserved("auth-") + id
	ok, err := st.Delete(krid)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func authIDs(st Store) ([]string, error) {
	krids, err := st.IDs(WithReservedPrefix("#auth"))
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

func provisionIDs(st Store) ([]string, error) {
	krids, err := st.IDs(WithReservedPrefix(provisionPrefix))
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(krids))
	for _, krid := range krids {
		id := parseProvisionID(krid)
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// authUnlock returns (id, master key) or ("", nil) if a matching auth
// is not found.
func authUnlock(st Store, key SecretKey) (string, SecretKey, error) {
	ids, err := authIDs(st)
	if err != nil {
		return "", nil, err
	}

	for _, id := range ids {
		var krid string
		if id == authV1ID {
			krid = "#auth"
		} else {
			krid = reserved("auth-") + id
		}

		item, err := getItem(st, krid, key)
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

func newProvisionID() string {
	b := rand32()
	return encoding.MustEncode(b[:], encoding.Base62)
}

func parseAuthID(s string) string {
	if s == "#auth" {
		return authV1ID
	}
	if !strings.HasPrefix(s, "#auth-") {
		return ""
	}
	return s[6:]
}

func parseProvisionID(s string) string {
	if !strings.HasPrefix(s, "#provision-") {
		return ""
	}
	return s[11:]
}

const authV1ID = "v1.auth"

// loadProvision loads provision for id.
func (k *Keyring) loadProvision(id string) (*Provision, error) {
	st := k.Store()
	logger.Debugf("Loading provision %s", id)

	b, err := st.Get(provisionPrefix + id)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, nil
	}
	var provision Provision
	if err := msgpack.Unmarshal(b, &provision); err != nil {
		return nil, err
	}
	return &provision, nil
}

// saveProvision saves provision.
func (k *Keyring) saveProvision(provision *Provision) error {
	logger.Debugf("Saving provision %s", provision.ID)
	st := k.Store()
	krid := provisionPrefix + provision.ID
	b, err := msgpack.Marshal(provision)
	if err != nil {
		return err
	}
	if err := st.Set(krid, b); err != nil {
		return err
	}
	return nil
}

// deleteProvision removes provision.
func (k *Keyring) deleteProvision(id string) (bool, error) {
	logger.Debugf("Deleting provision %s", id)
	st := k.Store()
	krid := provisionPrefix + id
	return st.Delete(krid)
}
