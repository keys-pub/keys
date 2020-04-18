package keyring

import (
	"os/exec"
	"runtime"
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

// Keyring defines an interface for accessing keyring items.
type Keyring interface {
	// Get item.
	// Requires Unlock().
	Get(id string) (*Item, error)

	// Create item.
	// Requires Unlock().
	Create(item *Item) error

	// Update item data.
	// Requires Unlock().
	Update(id string, b []byte) error

	// Delete item.
	// Doesn't require Unlock().
	Delete(id string) (bool, error)

	// List items.
	// Requires Unlock().
	// Items with IDs that start with "." or "#" are not returned by List.
	List(opts *ListOpts) ([]*Item, error)

	// Exists returns true it has the id.
	// Doesn't require Unlock().
	Exists(id string) (bool, error)

	// Setup auth, if no auth exists.
	// Returns ErrAlreadySetup if already setup.
	// Doesn't require Unlock().
	Setup(auth Auth) error
	// Provision new auth.
	// Requires Unlock().
	Provision(auth Auth) error
	// Deprovision auth.
	// Requires Unlock().
	Deprovision(auth Auth) (bool, error)

	// Unlock with auth.
	Unlock(auth Auth) error
	// Lock.
	Lock() error

	// Salt is default salt value, generated on first access and persisted
	// until ResetAuth() or Reset().
	// This salt value is not encrypted in the keyring.
	// Doesn't require Unlock().
	Salt() ([]byte, error)

	// IsSetup returns true if Keyring has been setup.
	// Doesn't require Unlock().
	IsSetup() (bool, error)

	// Reset keyring.
	// Doesn't require Unlock().
	Reset() error
}

// ListOpts ...
type ListOpts struct {
	Types []string
}

// Store is the cross platform keyring interface that a Keyring uses.
type Store interface {
	Get(service string, id string) ([]byte, error)
	Set(service string, id string, data []byte, typ string) error
	Delete(service string, id string) (bool, error)

	IDs(service string, prefix string, showHidden bool, showReserved bool) ([]string, error)
	List(service string, key SecretKey, opts *ListOpts) ([]*Item, error)
	Exists(service string, id string) (bool, error)
	Reset(service string) error
}

// System returns system keyring store.
func System() Store {
	return system()
}

// SystemOrFS returns system keyring store or FS if unavailable.
// On linux, if dbus is not available, uses the filesystem at ~/.keyring.
func SystemOrFS() Store {
	if runtime.GOOS == "linux" {
		path, err := exec.LookPath("dbus-launch")
		if err != nil || path == "" {
			dir, err := defaultFSDir()
			if err != nil {
				panic(err)
			}
			fs, err := FS(dir)
			if err != nil {
				panic(err)
			}
			return fs
		}
	}
	return system()
}

// SetupWithPassword sets up Keyring with a password.
func SetupWithPassword(kr Keyring, name string, password string) error {
	salt, err := kr.Salt()
	if err != nil {
		return err
	}
	auth, err := NewPasswordAuth(name, password, salt)
	if err != nil {
		return err
	}
	if err = kr.Setup(auth); err != nil {
		return err
	}
	return nil
}

// UnlockWithPassword unlocks a Keyring with a password.
func UnlockWithPassword(kr Keyring, name string, password string) error {
	salt, err := kr.Salt()
	if err != nil {
		return err
	}
	auth, err := NewPasswordAuth(name, password, salt)
	if err != nil {
		return err
	}
	if err = kr.Unlock(auth); err != nil {
		return err
	}
	return nil
}

func getItem(st Store, service string, id string, key SecretKey) (*Item, error) {
	if key == nil {
		return nil, ErrLocked
	}
	b, err := st.Get(service, id)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, nil
	}
	item, err := DecodeItem(b, key)
	if err != nil {
		return nil, err
	}
	return item, nil
}

const maxID = 254
const maxType = 32
const maxData = 2048

// TestSetItem (for testing)
var TestSetItem = setItem

func setItem(st Store, service string, item *Item, key SecretKey) error {
	if key == nil {
		return ErrLocked
	}
	if len(item.ID) > maxID {
		return ErrItemValueTooLarge
	}
	if len(item.Type) > maxType {
		return ErrItemValueTooLarge
	}
	if len(item.Data) > maxData {
		return ErrItemValueTooLarge
	}

	data, err := item.Marshal(key)
	if err != nil {
		return err
	}
	// Max for windows credential blob
	if len(data) > (5 * 512) {
		return ErrItemValueTooLarge
	}
	return st.Set(service, item.ID, []byte(data), item.Type)
}

// NewKeyring creates a new Keyring with backing Store.
//
// Use keyring.System() for the default system Store.
// On macOS this is the Keychain, on Windows wincred and linux SecretService.
//
// On other environments, you can use a filesystem backed Store by specifying
// keyring.FS(dir).
func NewKeyring(service string, st Store) (Keyring, error) {
	if service == "" {
		return nil, errors.Errorf("no service specified")
	}
	logger.Debugf("Keyring (%s)", service)
	kr, err := newKeyring(st, service)
	if err != nil {
		return nil, err
	}
	return kr, nil
}

func newKeyring(st Store, service string) (*keyring, error) {
	return &keyring{st: st, service: service}, nil
}

var _ Keyring = &keyring{}

type keyring struct {
	st      Store
	service string
	key     SecretKey
}

const reservedPrefix = "#"

func reserved(s string) string {
	return reservedPrefix + s
}

const hiddenPrefix = "."

func (k *keyring) Get(id string) (*Item, error) {
	if strings.HasPrefix(id, reservedPrefix) {
		return nil, errors.Errorf("keyring id prefix reserved %s", id)
	}
	return getItem(k.st, k.service, id, k.key)
}

func (k *keyring) Create(item *Item) error {
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

func (k *keyring) Update(id string, b []byte) error {
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

func (k *keyring) Delete(id string) (bool, error) {
	return k.st.Delete(k.service, id)
}

func (k *keyring) List(opts *ListOpts) ([]*Item, error) {
	return k.st.List(k.service, k.key, opts)
}

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

func (k *keyring) IDs(prefix string) ([]string, error) {
	return k.st.IDs(k.service, prefix, false, false)
}

func (k *keyring) Exists(id string) (bool, error) {
	return k.st.Exists(k.service, id)
}

func (k *keyring) Setup(auth Auth) error {
	setup, err := k.IsSetup()
	if err != nil {
		return err
	}
	if setup {
		return ErrAlreadySetup
	}
	key, err := authSetup(k.st, k.service, auth)
	if err != nil {
		return err
	}
	k.key = key
	return nil
}

func (k *keyring) Provision(auth Auth) error {
	if k.key == nil {
		return ErrLocked
	}
	if err := authProvision(k.st, k.service, auth, k.key); err != nil {
		return err
	}
	return nil
}

func (k *keyring) Deprovision(auth Auth) (bool, error) {
	if k.key == nil {
		return false, ErrLocked
	}
	return authDeprovision(k.st, k.service, auth)
}

func (k *keyring) Unlock(auth Auth) error {
	key, err := authUnlock(k.st, k.service, auth)
	if err != nil {
		return err
	}
	k.key = key
	return nil
}

func (k *keyring) Lock() error {
	k.key = nil
	return nil
}

func (k *keyring) Salt() ([]byte, error) {
	return salt(k.st, k.service)
}

func (k *keyring) IsSetup() (bool, error) {
	auths, err := k.st.IDs(k.service, reserved("auth"), false, true)
	if err != nil {
		return false, err
	}
	return len(auths) > 0, nil
}

func (k *keyring) Reset() error {
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

func contains(strs []string, s string) bool {
	for _, e := range strs {
		if e == s {
			return true
		}
	}
	return false
}
