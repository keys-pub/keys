package dstore

import (
	"context"
	"sort"
	"strings"

	"github.com/keys-pub/keys/dstore/events"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/tsutil"
)

func (m *Mem) EventAdd(ctx context.Context, path string, doc events.Document) (int64, error) {
	idx, err := m.EventsAdd(ctx, path, []events.Document{doc})
	return idx, err
}

// EventsAdd adds events to path.
func (m *Mem) EventsAdd(ctx context.Context, path string, docs []events.Document) (int64, error) {
	m.emtx.Lock()
	defer m.emtx.Unlock()
	doc, err := m.Get(ctx, path)
	if err != nil {
		return 0, err
	}
	idx := int64(0)
	if doc != nil {
		idx, _ = doc.Int64("idx")
	}
	for _, doc := range docs {
		idx++
		doc["idx"] = idx
		id := encoding.MustEncode(randBytes(32), encoding.Base62)
		lpath := Path(path, "log", id)
		if err := m.Create(ctx, lpath, From(doc)); err != nil {
			return 0, err
		}
	}

	if err := m.Set(ctx, path, map[string]interface{}{"idx": idx}, MergeAll()); err != nil {
		return 0, err
	}

	return idx, nil
}

func (m *Mem) Increment(ctx context.Context, path string, name string, n int64) (int64, int64, error) {
	m.emtx.Lock()
	defer m.emtx.Unlock()
	doc, err := m.Get(ctx, path)
	if err != nil {
		return 0, 0, err
	}
	val := int64(0)
	if doc != nil {
		v, ok := doc.Get(name)
		if err != nil {
			return 0, 0, err
		}
		if !ok {
			val = int64(0)
		} else {
			val = v.(int64)
		}
	}

	next := val + n
	if err := m.Set(ctx, path, map[string]interface{}{name: next}, MergeAll()); err != nil {
		return 0, 0, err
	}
	return next, next - n + 1, nil
}

func (m *Mem) EventPosition(ctx context.Context, path string) (*events.Position, error) {
	m.emtx.Lock()
	defer m.emtx.Unlock()
	doc, err := m.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	idx, _ := doc.Int64("idx")
	return &events.Position{
		Path:      path,
		Index:     idx,
		Timestamp: tsutil.Millis(doc.CreatedAt),
	}, nil
}

// EventPositions returns positions for event logs at the specified paths.
func (m *Mem) EventPositions(ctx context.Context, paths []string) (map[string]*events.Position, error) {
	m.emtx.Lock()
	defer m.emtx.Unlock()
	positions := map[string]*events.Position{}
	for _, path := range paths {
		doc, err := m.Get(ctx, path)
		if err != nil {
			return nil, err
		}
		if doc == nil {
			continue
		}
		idx, _ := doc.Int64("idx")
		positions[path] = &events.Position{
			Path:      path,
			Index:     idx,
			Timestamp: tsutil.Millis(doc.CreatedAt),
		}
	}
	return positions, nil
}

// EventsDelete removes all events at path.
func (m *Mem) EventsDelete(ctx context.Context, path string) (bool, error) {
	m.emtx.Lock()
	defer m.emtx.Unlock()
	ok, err := m.Delete(ctx, path)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	docs, err := m.list(ctx, Path(path, "log"))
	if err != nil {
		return false, err
	}
	for _, d := range docs {
		if _, err := m.Delete(ctx, d.Path); err != nil {
			return false, err
		}
	}

	return true, nil
}

func min(n1 int, n2 int) int {
	if n1 < n2 {
		return n1
	}
	return n2
}

// Events ...
func (m *Mem) Events(ctx context.Context, path string, opt ...events.Option) (events.Iterator, error) {
	m.emtx.Lock()
	defer m.emtx.Unlock()
	opts := events.NewOptions(opt...)

	out := make([]*events.Event, 0, m.paths.Size())

	for _, p := range m.paths.Strings() {
		if !strings.HasPrefix(p, Path(path, "log")+"/") {
			continue
		}
		doc, err := m.Get(ctx, p)
		if err != nil {
			return nil, err
		}
		if doc == nil {
			return nil, NewErrNotFound(p)
		}
		idx, _ := doc.Int64("idx")
		event := &events.Event{
			Document:  doc.Values(),
			Index:     idx,
			Timestamp: tsutil.Millis(doc.CreatedAt),
		}
		out = append(out, event)
	}
	switch opts.Direction {
	case events.Ascending:
		sort.Slice(out, func(i, j int) bool {
			return out[i].Index < out[j].Index
		})
	case events.Descending:
		sort.Slice(out, func(i, j int) bool {
			return out[i].Index > out[j].Index
		})
	}

	if opts.Index != 0 {
		logger.Debugf("Finding index for %d", opts.Index)
		found := -1
		switch opts.Direction {
		case events.Ascending:
			for i, c := range out {
				if c.Index > opts.Index {
					logger.Infof("Found version index %d", i)
					found = i
					break
				}
			}
		case events.Descending:
			for i, c := range out {
				if c.Index < opts.Index {
					logger.Infof("Found version index %d", i)
					found = i
					break
				}
			}
		}
		if found == -1 {
			out = []*events.Event{}
		} else {
			logger.Infof("Truncating from index %d", found)
			out = out[found:]
		}
	}

	if opts.Limit > 0 && len(out) > 0 {
		out = out[0:min(int(opts.Limit), len(out))]
	}

	return events.NewIterator(out), nil
}
