// Package keyring provides a cross-platform secure keyring.
package keyring

import (
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// ErrItemValueTooLarge is item value is too large.
// Item.ID is max of 254 bytes.
// Item.Type is max of 32 bytes.
// Item.Data is max of 2048 bytes.
var ErrItemValueTooLarge = errors.New("keyring item value is too large")

// ErrItemNotFound if item not found when trying to update.
var ErrItemNotFound = errors.New("keyring item not found")

// ErrItemAlreadyExists if item already exists trying to create.
var ErrItemAlreadyExists = errors.New("keyring item already exists")

// New creates a new Keyring with backing Store.
//
// Use keyring.System() for the default system Store.
// On macOS this is the Keychain, on Windows wincred and linux SecretService.
//
// Use keyring.SystemOrFS() for the default system Store or fallback to FS.
// Use keyring.Mem() for testing or ephemeral keys.
// Use keyring.FS(dir) for filesystem based keyring at dir.
func New(service string, st Store) (*Keyring, error) {
	if service == "" {
		return nil, errors.Errorf("no service specified")
	}
	logger.Debugf("Keyring (%s, %s)", service, st.Name())
	kr := newKeyring(service, st)
	return kr, nil
}

func newKeyring(service string, st Store) *Keyring {
	return &Keyring{service: service, st: st}
}

// Keyring stores encrypted keyring items.
type Keyring struct {
	st        Store
	service   string
	masterKey SecretKey
}

// Store used by Keyring.
func (k *Keyring) Store() Store {
	return k.st
}

// Get item.
// Requires Unlock().
func (k *Keyring) Get(id string) (*Item, error) {
	if strings.HasPrefix(id, ReservedPrefix) {
		return nil, errors.Errorf("keyring id prefix reserved %s", id)
	}
	return getItem(k.st, k.service, id, k.masterKey)
}

// Create item.
// Requires Unlock().
// Item IDs are not encrypted.
func (k *Keyring) Create(item *Item) error {
	if item.ID == "" {
		return errors.Errorf("empty id")
	}
	if strings.HasPrefix(item.ID, ReservedPrefix) {
		return errors.Errorf("keyring id prefix reserved %s", item.ID)
	}
	existing, err := getItem(k.st, k.service, item.ID, k.masterKey)
	if err != nil {
		return err
	}
	if existing != nil {
		return ErrItemAlreadyExists
	}

	return setItem(k.st, k.service, item, k.masterKey)
}

// Update item data.
// Requires Unlock().
func (k *Keyring) Update(id string, b []byte) error {
	if id == "" {
		return errors.Errorf("empty id")
	}
	if strings.HasPrefix(id, ReservedPrefix) {
		return errors.Errorf("keyring id prefix reserved %s", id)
	}

	item, err := getItem(k.st, k.service, id, k.masterKey)
	if err != nil {
		return err
	}
	if item == nil {
		return ErrItemNotFound
	}
	item.Data = b

	return setItem(k.st, k.service, item, k.masterKey)
}

// Delete item.
// Doesn't require Unlock().
func (k *Keyring) Delete(id string) (bool, error) {
	return k.st.Delete(k.service, id)
}

// List items.
// Requires Unlock().
// Items with ids that start with "." or "#" are not returned by List.
// If you need to list IDs only, see Keyring.IDs.
func (k *Keyring) List(opts ...ListOption) ([]*Item, error) {
	return List(k.st, k.service, k.masterKey, opts...)
}

// Setup auth, if no auth exists.
// Returns a provision identifier.
// Returns ErrAlreadySetup if already setup.
// Doesn't require Unlock().
func (k *Keyring) Setup(auth Auth) (string, error) {
	setup, err := k.IsSetup()
	if err != nil {
		return "", err
	}
	if setup {
		return "", ErrAlreadySetup
	}
	id, masterKey, err := authSetup(k.st, k.service, auth)
	if err != nil {
		return "", err
	}
	k.masterKey = masterKey
	return id, nil
}

// Provision new auth.
// Returns a provision identifier.
// Requires Unlock().
func (k *Keyring) Provision(auth Auth) (string, error) {
	if k.masterKey == nil {
		return "", ErrLocked
	}
	id, err := authProvision(k.st, k.service, auth, k.masterKey)
	if err != nil {
		return "", err
	}
	return id, nil
}

// Provisions are currently provisioned identifiers.
// Doesn't require Unlock().
func (k *Keyring) Provisions() ([]string, error) {
	return authProvisionIDs(k.st, k.service)
}

// Deprovision auth.
// Doesn't require Unlock().
func (k *Keyring) Deprovision(id string) (bool, error) {
	return authDeprovision(k.st, k.service, id)
}

// IsSetup returns true if Keyring has been setup.
// Doesn't require Unlock().
func (k *Keyring) IsSetup() (bool, error) {
	auths, err := k.st.IDs(k.service, WithReservedPrefix("auth"))
	if err != nil {
		return false, err
	}
	return len(auths) > 0, nil
}

// UnlockWithPassword unlocks keyring with a password.
func (k *Keyring) UnlockWithPassword(password string, setup bool) (Auth, error) {
	if password == "" {
		return nil, errors.Errorf("empty password")
	}
	salt, err := k.Salt()
	if err != nil {
		return nil, err
	}
	auth, err := NewPasswordAuth(password, salt)
	if err != nil {
		return nil, err
	}
	if setup {
		if _, err := k.Setup(auth); err != nil {
			return nil, err
		}
		return auth, nil
	}

	if _, err := k.Unlock(auth); err != nil {
		return nil, err
	}
	return auth, nil
}

// IDs returns item IDs.
// Doesn't require Unlock().
func (k *Keyring) IDs(opts ...IDsOption) ([]string, error) {
	return k.st.IDs(k.service, opts...)
}

// Exists returns true it has the id.
// Doesn't require Unlock().
func (k *Keyring) Exists(id string) (bool, error) {
	return k.st.Exists(k.service, id)
}

// Unlock with auth.
// Returns provision identifier used to unlock.
func (k *Keyring) Unlock(auth Auth) (string, error) {
	id, masterKey, err := authUnlock(k.st, k.service, auth)
	if err != nil {
		return "", err
	}
	if masterKey == nil {
		return "", ErrInvalidAuth
	}
	k.masterKey = masterKey
	return id, nil
}

// Lock the keyring.
func (k *Keyring) Lock() error {
	k.masterKey = nil
	return nil
}

// Salt is default salt value, generated on first access and persisted
// until Reset().
// This salt value is not encrypted in the keyring.
// Doesn't require Unlock().
func (k *Keyring) Salt() ([]byte, error) {
	return salt(k.st, k.service)
}

// Reset keyring.
// Doesn't require Unlock().
func (k *Keyring) Reset() error {
	if err := k.st.Reset(k.service); err != nil {
		return err
	}
	return k.Lock()
}

func resetDefault(st Store, service string) error {
	ids, err := st.IDs(service, Hidden(), Reserved())
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := st.Delete(service, id); err != nil {
			return err
		}
	}
	return nil
}

// ReservedPrefix are reserved items.
const ReservedPrefix = "#"

func reserved(s string) string {
	return ReservedPrefix + s
}

// HiddenPrefix are hidden items.
const HiddenPrefix = "."

// List items from Store.
func List(st Store, service string, key SecretKey, opts ...ListOption) ([]*Item, error) {
	var options ListOptions
	for _, o := range opts {
		o(&options)
	}

	if key == nil {
		return nil, ErrLocked
	}

	ids, err := st.IDs(service)
	if err != nil {
		return nil, err
	}
	items := make([]*Item, 0, len(ids))
	for _, id := range ids {
		b, err := st.Get(service, id)
		if err != nil {
			return nil, err
		}
		item, err := DecryptItem(b, key)
		if err != nil {
			return nil, err
		}
		if len(options.Types) != 0 && !contains(options.Types, item.Type) {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items, nil
}

func contains(strs []string, s string) bool {
	for _, e := range strs {
		if e == s {
			return true
		}
	}
	return false
}
