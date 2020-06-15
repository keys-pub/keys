// Package keyring provides a cross-platform secure keyring.
package keyring

import (
	"sort"

	"github.com/pkg/errors"
)

// ErrItemValueTooLarge is item value is too large.
// Item.ID is max of 254 bytes.
// Item.Type is max of 32 bytes.
// Item.Data is max of 2048 bytes.
var ErrItemValueTooLarge = errors.New("keyring item value is too large")

// New creates a new Keyring with backing Store.
//
// Use keyring.System for the default system Store.
// On macOS this is the Keychain, on Windows wincred and linux libsecret.
//
// Use keyring.Mem for testing or ephemeral keys.
// Use keyring.FS for a filesystem based keyring.
func New(opt ...Option) (*Keyring, error) {
	opts, err := newOptions(opt...)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Keyring (%s)", opts.st.Name())
	return newKeyring(opts.st), nil
}

func newKeyring(st Store) *Keyring {
	return &Keyring{
		st:   st,
		subs: newSubscribers(),
	}
}

// Keyring stores encrypted keyring items.
type Keyring struct {
	st        Store
	masterKey SecretKey
	subs      *subscribers
}

// Store used by Keyring.
func (k *Keyring) Store() Store {
	return k.st
}

// Get item.
// Requires Unlock().
func (k *Keyring) Get(id string) (*Item, error) {
	return getItem(k.st, id, k.masterKey)
}

// Set item.
// Requires Unlock().
// Item IDs are NOT encrypted.
func (k *Keyring) Set(item *Item) error {
	if item.ID == "" {
		return errors.Errorf("empty id")
	}
	if err := setItem(k.st, item, k.masterKey); err != nil {
		return err
	}
	k.subs.notify(SetEvent{ID: item.ID})
	return nil
}

// Delete item.
// Doesn't require Unlock().
func (k *Keyring) Delete(id string) (bool, error) {
	return k.st.Delete(id)
}

// List items.
// Requires Unlock().
// Items with ids that start with "." or "#" are not returned by List.
// If you need to list IDs only, see Keyring.IDs.
func (k *Keyring) List(opts ...ListOption) ([]*Item, error) {
	return List(k.st, k.masterKey, opts...)
}

// Status returns keyring status.
// Doesn't require Unlock().
func (k *Keyring) Status() (Status, error) {
	auths, err := k.st.IDs(WithReservedPrefix("auth"))
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
	return k.st.IDs(opts...)
}

// Exists returns true it has the id.
// Doesn't require Unlock().
func (k *Keyring) Exists(id string) (bool, error) {
	return k.st.Exists(id)
}

// Unlock with auth.
// Returns provision used to unlock.
func (k *Keyring) Unlock(key SecretKey) (*Provision, error) {
	id, masterKey, err := authUnlock(k.st, key)
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
	k.subs.notify(UnlockEvent{Provision: provision})
	return provision, nil
}

// MasterKey returns master key, if unlocked.
// It's not recommended to use this key for anything other than possibly
// deriving new keys.
func (k *Keyring) MasterKey() SecretKey {
	return k.masterKey
}

// SetMasterKey directly sets the master key.
// If the key is wrong this could leave the keyring in a weird state and should
// only be used in special circumstances.
// You probably want to use Setup or Unlock instead.
func (k *Keyring) SetMasterKey(mk SecretKey) {
	k.masterKey = mk
}

// Lock the keyring.
func (k *Keyring) Lock() error {
	k.masterKey = nil
	k.subs.notify(LockEvent{})
	return nil
}

// Reset keyring.
// Doesn't require Unlock().
func (k *Keyring) Reset() error {
	if err := k.st.Reset(); err != nil {
		return err
	}
	return k.Lock()
}

func resetDefault(st Store) error {
	ids, err := st.IDs(Reserved())
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := st.Delete(id); err != nil {
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

// List items from Store.
func List(st Store, key SecretKey, opts ...ListOption) ([]*Item, error) {
	var options ListOptions
	for _, o := range opts {
		o(&options)
	}

	if key == nil {
		return nil, ErrLocked
	}

	ids, err := st.IDs()
	if err != nil {
		return nil, err
	}
	items := make([]*Item, 0, len(ids))
	for _, id := range ids {
		b, err := st.Get(id)
		if err != nil {
			return nil, err
		}
		item, err := DecryptItem(b, key)
		if err != nil {
			return nil, err
		}
		if item.ID != id {
			return nil, errors.Errorf("item id doesn't match %s != %s", item.ID, id)
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
