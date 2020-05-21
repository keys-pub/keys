package keyring

import (
	"sort"
	"strings"

	"github.com/keys-pub/keys/keyring/options"
	"github.com/pkg/errors"
)

// NewMem returns an in memory Keyring useful for testing or ephemeral keys.
// The Keyring is unlocked (setup with a random key).
// If setup is true, the mem Keyring will be setup with a random key.
func NewMem(setup bool) *Keyring {
	kr := newKeyring("", Mem())
	if setup {
		_, err := kr.Setup(NewKeyAuth(rand32()))
		if err != nil {
			panic(err)
		}
	}
	return kr
}

// Mem returns in memory keyring.Store.
func Mem() Store {
	return &mem{map[string][]byte{}}
}

type mem struct {
	items map[string][]byte
}

func (k mem) Name() string {
	return "mem"
}

func (k mem) Get(service string, id string) ([]byte, error) {
	if b, ok := k.items[id]; ok {
		return b, nil
	}
	return nil, nil
}

func (k mem) Set(service string, id string, data []byte) error {
	if id == "" {
		return errors.Errorf("no id set")
	}
	k.items[id] = data
	return nil
}

func (k mem) Reset(service string) error {
	return resetDefault(k, service)
}

func (k mem) IDs(service string, opts *options.IDs) ([]string, error) {
	if opts == nil {
		opts = &options.IDs{}
	}
	prefix, showHidden, showReserved := opts.Prefix, opts.ShowHidden, opts.ShowReserved

	ids := make([]string, 0, len(k.items))
	for id := range k.items {
		if !showReserved && strings.HasPrefix(id, ReservedPrefix) {
			continue
		}
		if !showHidden && strings.HasPrefix(id, HiddenPrefix) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(id, prefix) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
	return ids, nil
}

func (k mem) Exists(service string, id string) (bool, error) {
	_, ok := k.items[id]
	return ok, nil
}

func (k mem) Delete(service string, id string) (bool, error) {
	if _, ok := k.items[id]; ok {
		delete(k.items, id)
		return true, nil
	}
	return false, nil
}
