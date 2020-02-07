package keyring

import (
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// NewMem returns an in memory Keyring useful for testing or ephemeral keys.
// The Keyring is unlocked (setup with a random key).
func NewMem() Keyring {
	kr, err := newKeyring(&mem{map[string][]byte{}}, "")
	if err != nil {
		panic(err)
	}
	// Unlock with random key.
	if err := kr.Unlock(NewKeyAuth(rand32())); err != nil {
		panic(err)
	}
	return kr
}

type mem struct {
	items map[string][]byte
}

func (k mem) Get(service string, id string) ([]byte, error) {
	if b, ok := k.items[id]; ok {
		return b, nil
	}
	return nil, nil
}

func (k mem) Set(service string, id string, data []byte, typ string) error {
	if id == "" {
		return errors.Errorf("no id set")
	}
	k.items[id] = data
	return nil
}

func (k mem) IDs(service string, prefix string, showHidden bool, showReserved bool) ([]string, error) {
	ids := make([]string, 0, len(k.items))
	for id := range k.items {
		if !showReserved && strings.HasPrefix(id, reservedPrefix) {
			continue
		}
		if !showHidden && strings.HasPrefix(id, hiddenPrefix) {
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
