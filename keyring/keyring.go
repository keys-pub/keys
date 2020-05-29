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

// Service name.
func (k *Keyring) Service() string {
	return k.service
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

// Status returns keyring status.
// Doesn't require Unlock().
func (k *Keyring) Status() (Status, error) {
	auths, err := k.st.IDs(k.service, WithReservedPrefix("auth"))
	if err != nil {
		return Unknown, err
	}
	setup := len(auths) > 0
	if !setup {
		return Setup, nil
	}
	if k.masterKey == nil {
		return Locked, nil
	}
	return Unlocked, nil
}

// Status for keyring.
type Status string

const (
	// Unknown status.
	Unknown Status = ""
	// Setup if setup needed.
	Setup Status = "setup"
	// Unlocked if unlocked.
	Unlocked Status = "unlocked"
	// Locked if locked.
	Locked Status = "locked"
)

// UnlockWithPassword unlocks keyring with a password.
// If setup is true, we are setting up the keyring auth for the first time.
// This is a convenience method, calling Setup or Unlock with KeyForPassword using the keyring#Salt.
func (k *Keyring) UnlockWithPassword(password string, setup bool) error {
	if password == "" {
		return errors.Errorf("empty password")
	}
	salt, err := k.Salt()
	if err != nil {
		return err
	}
	key, err := KeyForPassword(password, salt)
	if err != nil {
		return err
	}
	if setup {
		provision := NewProvision(PasswordAuth)
		if err := k.Setup(key, provision); err != nil {
			return err
		}
		return nil
	}

	if _, err := k.Unlock(key); err != nil {
		return err
	}
	return nil
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
func (k *Keyring) Unlock(key SecretKey) (*Provision, error) {
	id, masterKey, err := authUnlock(k.st, k.service, key)
	if err != nil {
		return nil, err
	}
	if masterKey == nil {
		return nil, ErrInvalidAuth
	}
	k.masterKey = masterKey

	provision, err := k.loadProvision(id)
	if err != nil {
		return nil, err
	}
	if provision == nil {
		provision = &Provision{ID: id}
	}

	return provision, nil
}

// MasterKey returns master key, if unlocked.
// It's not recommended to use this key for anything other than possibly
// deriving new keys.
func (k *Keyring) MasterKey() SecretKey {
	return k.masterKey
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
