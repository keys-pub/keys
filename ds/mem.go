package ds

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/keys-pub/keys/ds/events"
	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

var _ DocumentStore = &Mem{}
var _ events.Events = &Mem{}

// Mem is an in memory DocumentStore implementation.
type Mem struct {
	sync.RWMutex
	paths    *StringSet
	values   map[string][]byte
	metadata map[string]*metadata
	nowFn    func() time.Time
	inc      int64
}

type metadata struct {
	createTime time.Time
	updateTime time.Time
}

// NewMem creates an in memory DocumentStore implementation.
func NewMem() *Mem {
	return &Mem{
		paths:    NewStringSet(),
		values:   map[string][]byte{},
		metadata: map[string]*metadata{},
		nowFn:    time.Now,
	}
}

// Now returns current time.
func (m *Mem) Now() time.Time {
	return m.nowFn()
}

// SetTimeNow to use a custom time.Now.
func (m *Mem) SetTimeNow(nowFn func() time.Time) {
	m.nowFn = nowFn
}

// Create at path.
// ErrPathExists if entry already exists.
func (m *Mem) Create(ctx context.Context, path string, b []byte) error {
	return m.set(ctx, path, b, true)
}

// Set data at path.
func (m *Mem) Set(ctx context.Context, path string, b []byte) error {
	return m.set(ctx, path, b, false)
}

func (m *Mem) set(ctx context.Context, path string, b []byte, create bool) error {
	m.Lock()
	defer m.Unlock()

	path = Path(path)
	if path == "/" {
		return errors.Errorf("invalid path")
	}

	if len(PathComponents(path))%2 != 0 {
		return errors.Errorf("invalid path %s", path)
	}

	md, ok := m.metadata[path]

	if ok && create {
		return NewErrPathExists(path)
	}

	now := m.Now()
	if md == nil {
		md = &metadata{createTime: now, updateTime: now}
	} else {
		md.updateTime = now
	}

	if create {
		logger.Debugf("Create (mem) %s ", path)
	} else {
		logger.Debugf("Set (mem) %s", path)
	}

	m.values[path] = b
	m.metadata[path] = md
	m.paths.Add(path)
	return nil
}

// Get data at path.
func (m *Mem) Get(ctx context.Context, path string) (*Document, error) {
	m.RLock()
	defer m.RUnlock()
	path = Path(path)
	if len(PathComponents(path))%2 != 0 {
		return nil, errors.Errorf("invalid path %s", path)
	}
	return m.document(path), nil
}

func (m *Mem) document(path string) *Document {
	b, ok := m.values[path]
	if !ok {
		return nil
	}
	doc := NewDocument(path, b)
	md, ok := m.metadata[path]
	if ok {
		doc.CreatedAt = md.createTime
		doc.UpdatedAt = md.updateTime
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
func (m *Mem) DocumentIterator(ctx context.Context, parent string, opt ...DocumentsOption) (DocumentIterator, error) {
	m.RLock()
	defer m.RUnlock()

	docs, err := m.list(ctx, parent, opt...)
	if err != nil {
		return nil, err
	}
	return NewDocumentIterator(docs...), nil
}

// Documents ...
func (m *Mem) Documents(ctx context.Context, parent string, opt ...DocumentsOption) ([]*Document, error) {
	m.RLock()
	defer m.RUnlock()

	docs, err := m.list(ctx, parent, opt...)
	if err != nil {
		return nil, err
	}
	return docs, nil
}

func (m *Mem) list(ctx context.Context, parent string, opt ...DocumentsOption) ([]*Document, error) {
	opts := NewDocumentsOptions(opt...)

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

// Delete ...
func (m *Mem) Delete(ctx context.Context, path string) (bool, error) {
	m.Lock()
	defer m.Unlock()
	path = Path(path)

	docs, err := m.list(ctx, path)
	if err != nil {
		return false, err
	}
	if len(docs) == 0 {
		return m.delete(ctx, path)
	}
	for _, doc := range docs {
		ok, err := m.delete(ctx, doc.Path)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, errors.Errorf("failed to delete: missing %s", path)
		}
	}
	if _, err := m.delete(ctx, path); err != nil {
		return false, err
	}
	return true, nil
}
func (m *Mem) delete(ctx context.Context, path string) (bool, error) {
	path = Path(path)

	_, ok := m.values[path]
	if !ok {
		return false, nil
	}
	delete(m.values, path)
	delete(m.metadata, path)
	m.paths.Remove(path)
	return true, nil
}

// DeleteAll ...
func (m *Mem) DeleteAll(ctx context.Context, paths []string) error {
	for _, p := range paths {
		_, err := m.delete(ctx, p)
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
func (m *Mem) EventsAdd(ctx context.Context, path string, data [][]byte) ([]*events.Event, error) {
	out := make([]*events.Event, 0, len(data))
	for _, b := range data {
		m.inc++
		id := encoding.MustEncode(randBytes(32), encoding.Base62)
		event := &events.Event{
			Data:      b,
			Index:     m.inc,
			Timestamp: m.nowFn(),
		}
		b, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		path := Path(path, "log", id)
		if err := m.Create(ctx, path, b); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, nil
}

// EventsDelete removes events at path.
func (m *Mem) EventsDelete(ctx context.Context, path string) error {
	ok, err := m.Delete(ctx, path)
	if err != nil {
		return err
	}
	if !ok {
		return errors.Errorf("not found %s", path)
	}
	return nil
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
			return nil, errors.Errorf("path not found %s", p)
		}
		var event events.Event
		if err := json.Unmarshal(doc.Data, &event); err != nil {
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
