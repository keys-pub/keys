package keyring

import (
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// Mem Store option.
func Mem() Option {
	return func(o *Options) error {
		st := NewMem()
		o.st = st
		return nil
	}
}

// NewMem returns an in memory Keyring useful for testing or ephemeral keys.
func NewMem() Store {
	return &mem{map[string][]byte{}}
}

type mem struct {
	items map[string][]byte
}

func (k mem) Name() string {
	return "mem"
}

func (k mem) Get(id string) ([]byte, error) {
	if b, ok := k.items[id]; ok {
		return b, nil
	}
	return nil, nil
}

func (k mem) Set(id string, data []byte) error {
	if id == "" {
		return errors.Errorf("no id set")
	}
	k.items[id] = data
	return nil
}

func (k mem) Reset() error {
	return resetDefault(k)
}

func (k mem) IDs(opts ...IDsOption) ([]string, error) {
	options := NewIDsOptions(opts...)
	prefix, showHidden, showReserved := options.Prefix, options.Hidden, options.Reserved

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

func (k mem) Exists(id string) (bool, error) {
	_, ok := k.items[id]
	return ok, nil
}

func (k mem) Delete(id string) (bool, error) {
	if _, ok := k.items[id]; ok {
		delete(k.items, id)
		return true, nil
	}
	return false, nil
}
