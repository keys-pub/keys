package keyring

import (
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// ErrItemValueTooLarge is item value is too large.
// ID is max of 254 bytes.
// Type is max of 32 bytes.
// Data is max of 2048 bytes.
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
	st      Store
	service string
	key     SecretKey
}

// Get item.
// Requires Unlock().
func (k *Keyring) Get(id string) (*Item, error) {
	if strings.HasPrefix(id, reservedPrefix) {
		return nil, errors.Errorf("keyring id prefix reserved %s", id)
	}
	return getItem(k.st, k.service, id, k.key)
}

// Create item.
// Requires Unlock().
// Item IDs are not encrypted.
func (k *Keyring) Create(item *Item) error {
	if item.ID == "" {
		return errors.Errorf("no id")
	}
	if strings.HasPrefix(item.ID, reservedPrefix) {
		return errors.Errorf("keyring id prefix reserved %s", item.ID)
	}
	existing, err := getItem(k.st, k.service, item.ID, k.key)
	if err != nil {
		return err
	}
	if existing != nil {
		return ErrItemAlreadyExists
	}

	return setItem(k.st, k.service, item, k.key)
}

// Update item data.
// Requires Unlock().
func (k *Keyring) Update(id string, b []byte) error {
	if id == "" {
		return errors.Errorf("no id")
	}
	if strings.HasPrefix(id, reservedPrefix) {
		return errors.Errorf("keyring id prefix reserved %s", id)
	}

	item, err := getItem(k.st, k.service, id, k.key)
	if err != nil {
		return err
	}
	if item == nil {
		return ErrItemNotFound
	}
	item.Data = b

	return setItem(k.st, k.service, item, k.key)
}

// Delete item.
// Doesn't require Unlock().
func (k *Keyring) Delete(id string) (bool, error) {
	return k.st.Delete(k.service, id)
}

// ListOpts ...
type ListOpts struct {
	Types []string
}

// List items.
// Requires Unlock().
// Items with ids that start with "." are not returned by List.
// If you need to list IDs only, see Keyring.IDs.
func (k *Keyring) List(opts *ListOpts) ([]*Item, error) {
	return k.st.List(k.service, k.key, opts)
}

// UnlockWithPassword unlocks a Keyring with a password.
func (k *Keyring) UnlockWithPassword(password string) error {
	salt, err := k.Salt()
	if err != nil {
		return err
	}
	auth, err := NewPasswordAuth(password, salt)
	if err != nil {
		return err
	}
	if err = k.Unlock(auth); err != nil {
		return err
	}
	return nil
}

// IDs returns item IDs.
// Doesn't require Unlock().
func (k *Keyring) IDs(prefix string) ([]string, error) {
	return k.st.IDs(k.service, prefix, false, false)
}

// Exists returns true it has the id.
// Doesn't require Unlock().
func (k *Keyring) Exists(id string) (bool, error) {
	return k.st.Exists(k.service, id)
}

// Unlock with auth.
func (k *Keyring) Unlock(auth Auth) error {
	key, err := unlock(k.st, k.service, auth)
	if err != nil {
		return err
	}
	k.key = key
	return nil
}

// Lock the keyring.
func (k *Keyring) Lock() error {
	k.key = nil
	return nil
}

// Salt is default salt value, generated on first access and persisted
// until ResetAuth() or Reset().
// This salt value is not encrypted in the keyring.
// Doesn't require Unlock().
func (k *Keyring) Salt() ([]byte, error) {
	return salt(k.st, k.service)
}

// Authed returns true if Keyring has ever been unlocked.
// Doesn't require Unlock().
func (k *Keyring) Authed() (bool, error) {
	return k.st.Exists(k.service, reserved("auth"))
}

// func (k *keyring) ResetAuth() error {
// 	if _, err := k.st.remove(k.service, reserved("salt")); err != nil {
// 		return err
// 	}
// 	if _, err := k.st.remove(k.service, reserved("auth")); err != nil {
// 		return err
// 	}
// 	return nil
// }

// Reset keyring.
// Doesn't require Unlock().
func (k *Keyring) Reset() error {
	if err := k.st.Reset(k.service); err != nil {
		return err
	}
	return k.Lock()
}

func resetDefault(st Store, service string) error {
	ids, err := st.IDs(service, "", true, true)
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

const reservedPrefix = "#"

func reserved(s string) string {
	return reservedPrefix + s
}

const hiddenPrefix = "."

func listDefault(st Store, service string, key SecretKey, opts *ListOpts) ([]*Item, error) {
	if opts == nil {
		opts = &ListOpts{}
	}
	if key == nil {
		return nil, ErrLocked
	}

	ids, err := st.IDs(service, "", false, false)
	if err != nil {
		return nil, err
	}
	items := make([]*Item, 0, len(ids))
	for _, id := range ids {
		b, err := st.Get(service, id)
		if err != nil {
			return nil, err
		}
		item, err := DecodeItem(b, key)
		if err != nil {
			return nil, err
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

func contains(strs []string, s string) bool {
	for _, e := range strs {
		if e == s {
			return true
		}
	}
	return false
}
