package dstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/keys-pub/keys/dstore/events"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

var _ Documents = &Mem{}
var _ events.Events = &Mem{}

// Mem is an in memory Documents implementation.
type Mem struct {
	sync.RWMutex
	paths  *StringSet
	values map[string]*Document
	clock  tsutil.Clock
}

// NewMem creates an in memory Documents implementation.
func NewMem() *Mem {
	return &Mem{
		paths:  NewStringSet(),
		values: map[string]*Document{},
		clock:  tsutil.NewClock(),
	}
}

// Now returns current time.
func (m *Mem) Now() time.Time {
	return m.clock.Now()
}

// SetClock to use a custom Clock (for testing).
func (m *Mem) SetClock(clock tsutil.Clock) {
	m.clock = clock
}

// Create document at path.
// ErrPathExists if entry already exists.
func (m *Mem) Create(ctx context.Context, path string, values map[string]interface{}) error {
	return m.set(ctx, path, values, true, false)
}

// Set document at path.
func (m *Mem) Set(ctx context.Context, path string, values map[string]interface{}, opt ...SetOption) error {
	opts := NewSetOptions(opt...)
	return m.set(ctx, path, values, false, opts.MergeAll)
}

func (m *Mem) set(ctx context.Context, path string, values map[string]interface{}, create bool, mergeAll bool) error {
	m.Lock()
	defer m.Unlock()

	path = Path(path)
	if path == "/" {
		return errors.Errorf("invalid path")
	}

	if len(PathComponents(path))%2 != 0 {
		return errors.Errorf("invalid path %s", path)
	}

	doc, ok := m.values[path]

	if ok && create {
		return NewErrPathExists(path)
	}

	now := m.Now()
	if doc == nil {
		doc = NewDocument(path).With(values)
		doc.CreatedAt = now
		doc.UpdatedAt = now
	} else {
		if mergeAll {
			for k, v := range values {
				doc.Set(k, v)
			}
		} else {
			doc.SetAll(values)
		}
		doc.UpdatedAt = now
	}

	if create {
		logger.Debugf("Create (mem) %s ", path)
	} else {
		logger.Debugf("Set (mem) %s", path)
	}

	m.values[path] = doc
	m.paths.Add(path)
	return nil
}

// Update document.
func (m *Mem) Update(ctx context.Context, path string, values map[string]interface{}) error {
	m.Lock()
	defer m.Unlock()

	path = Path(path)
	if path == "/" {
		return errors.Errorf("invalid path")
	}
	if len(PathComponents(path))%2 != 0 {
		return errors.Errorf("invalid path %s", path)
	}
	doc, ok := m.values[path]
	if !ok {
		return NewErrNotFound(path)
	}
	for k, v := range values {
		doc.Set(k, v)
	}
	return nil
}

// Get document at path.
func (m *Mem) Get(ctx context.Context, path string) (*Document, error) {
	m.RLock()
	defer m.RUnlock()
	path = Path(path)
	if len(PathComponents(path))%2 != 0 {
		return nil, errors.Errorf("invalid path %s", path)
	}
	return m.document(path), nil
}

// Load path into value.
func (m *Mem) Load(ctx context.Context, path string, v interface{}) (bool, error) {
	return Load(ctx, m, path, v)
}

func (m *Mem) document(path string) *Document {
	doc, ok := m.values[path]
	if !ok {
		return nil
	}
	return doc
}

// Collections ...
func (m *Mem) Collections(ctx context.Context, parent string) ([]*Collection, error) {
	if Path(parent) != "/" {
		// TODO: Support nested collections
		return nil, errors.Errorf("only root collections supported")
	}
	collections := []*Collection{}
	count := map[string]int{}
	for _, path := range m.paths.Sorted() {
		col := PathFirst(path)
		colv, ok := count[col]
		if !ok {
			collections = append(collections, &Collection{Path: Path(col)})
			count[col] = 1
		} else {
			count[col] = colv + 1
		}
	}
	return collections, nil
}

// DocumentIterator ...
func (m *Mem) DocumentIterator(ctx context.Context, parent string, opt ...Option) (Iterator, error) {
	m.RLock()
	defer m.RUnlock()

	docs, err := m.list(ctx, parent, opt...)
	if err != nil {
		return nil, err
	}
	return NewIterator(docs...), nil
}

// Documents ...
func (m *Mem) Documents(ctx context.Context, parent string, opt ...Option) ([]*Document, error) {
	m.RLock()
	defer m.RUnlock()

	docs, err := m.list(ctx, parent, opt...)
	if err != nil {
		return nil, err
	}
	return docs, nil
}

func (m *Mem) list(ctx context.Context, parent string, opt ...Option) ([]*Document, error) {
	opts := NewOptions(opt...)

	path := Path(parent)
	if path == "/" {
		return nil, errors.Errorf("list root not supported")
	}

	docs := []*Document{}
	var prefix string
	if opts.Prefix != "" {
		prefix = Path(path, opts.Prefix)
	}

	for _, p := range m.paths.Sorted() {
		if !strings.HasPrefix(p, path+"/") {
			continue
		}
		if prefix != "" && !strings.HasPrefix(p, prefix) {
			continue
		}
		doc := m.document(p)
		if doc == nil {
			return nil, errors.Errorf("missing document in List")
		}
		if opts.Where != nil {
			if opts.Where.Op != "==" {
				return nil, errors.Errorf("unsupported op")
			}
			v, ok := doc.Get(opts.Where.Name)
			if !ok {
				continue
			}
			if !cmp.Equal(v, opts.Where.Value) {
				continue
			}
		}
		if opts.NoData {
			doc = &Document{Path: doc.Path, CreatedAt: doc.CreatedAt, UpdatedAt: doc.UpdatedAt}
		}
		docs = append(docs, doc)
	}
	idx := opts.Index
	if idx > len(docs) {
		idx = len(docs)
	}
	if idx > 0 {
		docs = docs[idx:]
	}
	if opts.Limit != 0 && len(docs) > opts.Limit {
		docs = docs[:opts.Limit]
	}
	return docs, nil
}

// Delete document at path.
func (m *Mem) Delete(ctx context.Context, path string) (bool, error) {
	path = Path(path)

	_, ok := m.values[path]
	if !ok {
		return false, nil
	}
	delete(m.values, path)
	m.paths.Remove(path)
	return true, nil
}

// DeleteAll deletes all documents at path.
func (m *Mem) DeleteAll(ctx context.Context, paths []string) error {
	for _, p := range paths {
		_, err := m.Delete(ctx, p)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetAll paths.
func (m *Mem) GetAll(ctx context.Context, paths []string) ([]*Document, error) {
	docs := make([]*Document, 0, len(paths))
	for _, p := range paths {
		doc := m.document(Path(p))
		if doc == nil {
			continue
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

// Exists returns true if path exists.
func (m *Mem) Exists(ctx context.Context, path string) (bool, error) {
	_, ok := m.values[Path(path)]
	return ok, nil
}

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// EventsAdd adds events to path.
func (m *Mem) EventsAdd(ctx context.Context, path string, data [][]byte) ([]*events.Event, int64, error) {
	out := make([]*events.Event, 0, len(data))
	doc, err := m.Get(ctx, path)
	if err != nil {
		return nil, 0, err
	}
	idx := int64(0)
	if doc != nil {
		idx, _ = doc.Int64("idx")
	}
	for _, b := range data {
		idx++
		if err := m.Set(ctx, path, map[string]interface{}{"idx": idx}, MergeAll()); err != nil {
			return nil, 0, err
		}

		id := encoding.MustEncode(randBytes(32), encoding.Base62)
		event := &events.Event{
			Data:      b,
			Index:     idx,
			Timestamp: m.clock.NowMillis(),
		}
		b, err := json.Marshal(event)
		if err != nil {
			return nil, 0, err
		}
		path := Path(path, "log", id)
		if err := m.Create(ctx, path, Data(b)); err != nil {
			return nil, 0, err
		}
		out = append(out, event)
	}
	return out, idx, nil
}

// EventPositions returns positions for event logs at the specified paths.
func (m *Mem) EventPositions(ctx context.Context, paths []string) (map[string]*events.Position, error) {
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
		var event events.Event
		if err := json.Unmarshal(doc.Bytes("data"), &event); err != nil {
			return nil, err
		}
		out = append(out, &event)
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
