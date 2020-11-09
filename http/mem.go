package http

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

// Mem is a in memory key value store.
type Mem struct {
	sync.Mutex
	kv    map[string]*entry
	clock tsutil.Clock
}

// NonceCheck ...
func (m *Mem) NonceCheck(ctx context.Context, nonce string) error {
	val, err := m.Get(ctx, nonce)
	if err != nil {
		return err
	}
	if val != "" {
		return errors.Errorf("nonce collision")
	}
	if err := m.Set(ctx, nonce, "1"); err != nil {
		return err
	}
	if err := m.Expire(ctx, nonce, time.Hour); err != nil {
		return err
	}
	return nil
}

// NewMem creates a Mem key value store.
func NewMem(clock tsutil.Clock) *Mem {
	return &Mem{
		kv:    map[string]*entry{},
		clock: clock,
	}
}

type entry struct {
	Value  string
	Expire time.Time
}

// Get ...
func (m *Mem) Get(ctx context.Context, k string) (string, error) {
	m.Lock()
	defer m.Unlock()
	e, err := m.get(ctx, k)
	if err != nil {
		return "", err
	}
	if e == nil {
		return "", nil
	}
	return e.Value, nil
}

func (m *Mem) get(ctx context.Context, k string) (*entry, error) {
	e, ok := m.kv[k]
	if !ok {
		return nil, nil
	}
	if e.Expire.IsZero() {
		return e, nil
	}
	now := m.clock.Now()
	if e.Expire.Equal(now) || now.After(e.Expire) {
		return nil, nil
	}
	return e, nil
}

// Expire ...
func (m *Mem) Expire(ctx context.Context, k string, dt time.Duration) error {
	m.Lock()
	defer m.Unlock()
	t := m.clock.Now()
	t = t.Add(dt)
	e, err := m.get(ctx, k)
	if err != nil {
		return err
	}
	e.Expire = t
	return m.set(ctx, k, e)
}

// Delete ..
func (m *Mem) Delete(ctx context.Context, k string) error {
	m.Lock()
	defer m.Unlock()
	delete(m.kv, k)
	return nil
}

// Set ...
func (m *Mem) Set(ctx context.Context, k string, v string) error {
	m.Lock()
	defer m.Unlock()
	return m.set(ctx, k, &entry{Value: v})
}

func (m *Mem) set(ctx context.Context, k string, e *entry) error {
	m.kv[k] = e
	return nil
}

// Increment ...
func (m *Mem) Increment(ctx context.Context, k string) (int64, error) {
	m.Lock()
	defer m.Unlock()
	e, err := m.get(ctx, k)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(e.Value, 10, 64)
	if err != nil {
		return 0, err
	}
	n++
	inc := strconv.FormatInt(n, 10)
	e.Value = inc
	return n, m.set(ctx, k, e)
}
