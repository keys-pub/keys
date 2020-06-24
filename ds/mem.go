package ds

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

var _ DocumentStore = &Mem{}
var _ Changes = &Mem{}

// Mem is an in memory DocumentStore implementation.
type Mem struct {
	sync.RWMutex
	paths       *StringSet
	values      map[string][]byte
	metadata    map[string]*metadata
	nowFn       func() time.Time
	incrementFn IncrementFn
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

// IncrementFn describes an auto increment function.
type IncrementFn func(ctx context.Context) (int64, error)

// SetIncrementFn sets an auto increment function.
func (m *Mem) SetIncrementFn(incrementFn IncrementFn) {
	m.incrementFn = incrementFn
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
func (m *Mem) Collections(ctx context.Context, parent string) (CollectionIterator, error) {
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
	return NewCollectionIterator(collections), nil
}

// Documents ...
func (m *Mem) Documents(ctx context.Context, parent string, opt ...DocumentsOption) (DocumentIterator, error) {
	docs, err := m.list(ctx, parent, opt...)
	if err != nil {
		return nil, err
	}
	return NewDocumentIterator(docs...), nil
}

func (m *Mem) list(ctx context.Context, parent string, opt ...DocumentsOption) ([]*Document, error) {
	m.RLock()
	defer m.RUnlock()
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

// ChangesAdd ...
func (m *Mem) ChangesAdd(ctx context.Context, collection string, data [][]byte) error {
	if m.incrementFn == nil {
		return errors.Errorf("no increment fn set")
	}
	for _, b := range data {
		version, err := m.incrementFn(ctx)
		if err != nil {
			return err
		}
		b, err := json.Marshal(Change{
			Data:      b,
			Version:   version,
			Timestamp: m.nowFn(),
		})
		if err != nil {
			return err
		}
		id := encoding.MustEncode(randBytes(32), encoding.Base62)
		path := Path(collection, id)
		if err := m.Create(ctx, path, b); err != nil {
			return err
		}
	}
	return nil
}

func min(n1 int, n2 int) int {
	if n1 < n2 {
		return n1
	}
	return n2
}

// Changes ...
func (m *Mem) Changes(ctx context.Context, collection string, version int64, limit int, direction Direction) (ChangeIterator, error) {
	changes := make([]*Change, 0, m.paths.Size())

	for _, p := range m.paths.Strings() {
		if !strings.HasPrefix(p, Path(collection)+"/") {
			continue
		}
		doc, err := m.Get(ctx, p)
		if err != nil {
			return nil, err
		}
		if doc == nil {
			return nil, errors.Errorf("path not found %s", p)
		}
		var change Change
		if err := json.Unmarshal(doc.Data, &change); err != nil {
			return nil, err
		}
		changes = append(changes, &change)
	}
	switch direction {
	case Ascending:
		sort.Slice(changes, func(i, j int) bool {
			return changes[i].Version < changes[j].Version
		})
	case Descending:
		sort.Slice(changes, func(i, j int) bool {
			return changes[i].Version > changes[j].Version
		})
	}

	if version != 0 {
		logger.Debugf("Finding index for %d", version)
		index := -1
		switch direction {
		case Ascending:
			for i, c := range changes {
				if c.Version > version {
					logger.Infof("Found version index %d", i)
					index = i
					break
				}
			}
		case Descending:
			for i, c := range changes {
				if c.Version < version {
					logger.Infof("Found version index %d", i)
					index = i
					break
				}
			}
		}
		if index == -1 {
			changes = []*Change{}
		} else {
			logger.Infof("Truncating from index %d", index)
			changes = changes[index:]
		}
	}

	if limit > 0 && len(changes) > 0 {
		changes = changes[0:min(limit, len(changes))]
	}

	return NewChangeIterator(changes), nil
}
