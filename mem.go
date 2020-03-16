package keys

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var _ DocumentStore = &Mem{}
var _ Changes = &Mem{}

// Mem is an in memory DocumentStore implementation.
type Mem struct {
	sync.RWMutex
	collections *StringSet
	paths       *StringSet
	values      map[string][]byte
	metadata    map[string]*metadata
	watch       map[string]*watch
	watchMtx    sync.Mutex
	nowFn       func() time.Time
}

type metadata struct {
	createTime time.Time
	updateTime time.Time
}

// NewMem creates an in memory DocumentStore implementation.
func NewMem() *Mem {
	return &Mem{
		collections: NewStringSet(),
		paths:       NewStringSet(),
		values:      map[string][]byte{},
		metadata:    map[string]*metadata{},
		watch:       map[string]*watch{},
		watchMtx:    sync.Mutex{},
		nowFn:       time.Now,
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
	return m.setAndWatch(ctx, path, b, true)
}

// Set data at path.
func (m *Mem) Set(ctx context.Context, path string, b []byte) error {
	return m.setAndWatch(ctx, path, b, false)
}

func (m *Mem) setAndWatch(ctx context.Context, path string, b []byte, create bool) error {
	path = Path(path)
	if err := m.set(ctx, path, b, create); err != nil {
		return err
	}

	root := PathComponents(path)[0]
	w, ok := m.watch[Path(root)]
	if ok {
		e := &WatchEvent{Path: path, Status: WatchStatusData}
		w.ln(e)
	}

	return nil
}

func (m *Mem) set(ctx context.Context, path string, b []byte, create bool) error {
	m.Lock()
	defer m.Unlock()

	if len(PathComponents(path)) != 2 {
		return errors.Errorf("invalid path %s", path)
	}

	collection := FirstPathComponent(path)
	if collection == "" {
		return errors.Errorf("invalid path")
	}
	m.collections.Add(collection)

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
	if len(PathComponents(path)) != 2 {
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
		return nil, errors.Errorf("only root collections supported")
	}
	parents := m.collections.Sorted()
	col := make([]*Collection, 0, len(parents))
	for _, p := range parents {
		col = append(col, &Collection{Path: Path(p)})
	}
	return NewCollectionIterator(col), nil
}

// Documents ...
func (m *Mem) Documents(ctx context.Context, parent string, opts *DocumentsOpts) (DocumentIterator, error) {
	docs, err := m.list(ctx, parent, opts)
	if err != nil {
		return nil, err
	}
	return NewDocumentIterator(docs), nil
}

func (m *Mem) list(ctx context.Context, parent string, opts *DocumentsOpts) ([]*Document, error) {
	m.RLock()
	defer m.RUnlock()
	if opts == nil {
		opts = &DocumentsOpts{}
	}

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

type watch struct {
	ln WatchLn
	wg *sync.WaitGroup
}

// URI ...
func (m *Mem) URI() string {
	return "mem://"
}

// GetAll paths
func (m *Mem) GetAll(ctx context.Context, paths []string) ([]*Document, error) {
	docs := make([]*Document, 0, len(paths))
	for _, p := range paths {
		doc := m.document(Path(p))
		if doc == nil {
			return nil, errors.Errorf("missing document in GetAll")
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

// ChangeAdd ...
func (m *Mem) ChangeAdd(ctx context.Context, name string, ref string) error {
	path := activityPath(name, ref)
	b, err := json.Marshal(Change{
		Path:      ref,
		Timestamp: m.nowFn(),
	})
	if err != nil {
		return err
	}
	return m.Create(ctx, path, b)
}

func activityPath(name string, ref string) string {
	s := strings.ReplaceAll(ref, "/", "-")
	return Path(name, s)
}

// Change ...
func (m *Mem) Change(ctx context.Context, name string, ref string) (*Change, error) {
	path := activityPath(name, ref)
	doc, err := m.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	var change Change
	if err := json.Unmarshal(doc.Data, &change); err != nil {
		return nil, err
	}
	return &change, nil
}

func min(n1 int, n2 int) int {
	if n1 < n2 {
		return n1
	}
	return n2
}

// Changes ...
func (m *Mem) Changes(ctx context.Context, name string, ts time.Time, limit int, direction Direction) ([]*Change, time.Time, error) {
	changes := make([]*Change, 0, m.paths.Size())

	for _, p := range m.paths.Strings() {
		if !strings.HasPrefix(p, Path(name)+"/") {
			continue
		}
		doc, err := m.Get(ctx, p)
		if err != nil {
			return nil, time.Time{}, err
		}
		if doc == nil {
			return nil, time.Time{}, errors.Errorf("path not found %s", p)
		}
		var change Change
		if err := json.Unmarshal(doc.Data, &change); err != nil {
			return nil, time.Time{}, err
		}
		changes = append(changes, &change)
	}
	switch direction {
	case Ascending:
		sort.Slice(changes, func(i, j int) bool {
			if changes[i].Timestamp == changes[j].Timestamp {
				return changes[i].Path < changes[j].Path
			}
			return changes[i].Timestamp.Before(changes[j].Timestamp)
		})
	case Descending:
		sort.Slice(changes, func(i, j int) bool {
			if changes[i].Timestamp == changes[j].Timestamp {
				return changes[i].Path > changes[j].Path
			}
			return changes[i].Timestamp.After(changes[j].Timestamp)
		})
	}

	if !ts.IsZero() {
		index := 0
		switch direction {
		case Ascending:
			for i, c := range changes {
				if c.Timestamp == ts || c.Timestamp.After(ts) {
					index = i
					break
				}
			}
		case Descending:
			for i, c := range changes {
				if c.Timestamp == ts || c.Timestamp.Before(ts) {
					index = i
					break
				}
			}
		}
		changes = changes[index:]
	}

	if limit > 0 {
		changes = changes[0:min(limit, len(changes))]
	}

	to := ts
	if len(changes) > 0 {
		to = changes[len(changes)-1].Timestamp
	}

	return changes, to, nil
}

// Watch ...
func (m *Mem) Watch(path string, ln WatchLn) error {
	m.watchMtx.Lock()
	_, ok := m.watch[path]
	if ok {
		m.watchMtx.Unlock()
		return errors.Errorf("already watching %s", path)
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	m.watch[path] = &watch{
		ln: ln,
		wg: wg,
	}
	ln(&WatchEvent{Path: path, Status: WatchStatusStarting})
	m.watchMtx.Unlock()
	wg.Wait()
	return nil
}

// StopWatching ...
func (m *Mem) StopWatching(path string) {
	m.watchMtx.Lock()
	defer m.watchMtx.Unlock()
	m.stopWatching(path)
}

func (m *Mem) stopWatching(path string) {
	w, ok := m.watch[path]
	if ok {
		w.ln(&WatchEvent{Path: path, Status: WatchStatusStopping})
		w.wg.Done()
		delete(m.watch, path)
	}
}

// StopWatchingAll ...
func (m *Mem) StopWatchingAll() {
	m.watchMtx.Lock()
	defer m.watchMtx.Unlock()
	for p := range m.watch {
		m.stopWatching(p)
	}
}
