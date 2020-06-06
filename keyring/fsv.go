package keyring

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

type fsv struct {
	sync.Mutex
	dir   string
	cache *files
	nowFn func() time.Time
}

var _ Store = &fsv{}

// newFSV creates a versioned FS store.
func newFSV(dir string) (Store, error) {
	if dir == "" || dir == "/" {
		return nil, errors.Errorf("invalid directory %q", dir)
	}
	return &fsv{dir: dir, nowFn: time.Now}, nil
}

func (r *fsv) Name() string {
	return "fsv"
}

func (r *fsv) Get(id string) ([]byte, error) {
	if id == "" {
		return nil, errors.Errorf("failed to get keyring item: no id specified")
	}
	if id == "." || id == ".." || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return nil, errors.Errorf("failed to get keyring item: invalid id %q", id)
	}
	// logger.Debugf("Get %s", id)

	files, err := r.checkCache()
	if err != nil {
		return nil, err
	}
	file, ok := files.current[id]
	if !ok {
		return nil, nil
	}
	if file.deleted {
		return nil, nil
	}
	path := filepath.Join(r.dir, file.Name())
	return ioutil.ReadFile(path) // #nosec
}

func (r *fsv) Set(id string, data []byte) error {
	if id == "" {
		return errors.Errorf("no id specified")
	}
	// logger.Debugf("Set %s", id)
	now := r.nowFn()

	files, err := r.checkCache()
	if err != nil {
		return err
	}

	file, ok := files.current[id]
	if !ok {
		file = newFile(id, 1, now)
		logger.Debugf("Set (new) %s", file)
	} else {
		file = file.Next(now)
		logger.Debugf("Set (next) %s", file)
	}

	name := file.Name()
	msg := fmt.Sprintf("Set %s (%d)", id, file.version)
	return r.add(name, data, msg)
}

func (r *fsv) add(name string, data []byte, msg string) error {
	if err := os.MkdirAll(r.dir, 0700); err != nil {
		return err
	}

	path := filepath.Join(r.dir, name)
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		return errors.Wrapf(err, "failed to write file")
	}

	// Clear cache
	r.cache = nil

	return nil
}

func (r *fsv) Delete(id string) (bool, error) {
	if id == "" {
		return false, errors.Errorf("no id specified")
	}

	files, err := r.checkCache()
	if err != nil {
		return false, err
	}

	file, ok := files.current[id]
	if !ok {
		return false, nil
	}
	if file.deleted {
		return false, nil
	}

	next := file.Next(r.nowFn())
	next.deleted = true
	name := next.Name()

	msg := fmt.Sprintf("Delete %s (%d)", id, next.version)
	if err := r.add(name, []byte{}, msg); err != nil {
		return false, err
	}

	return true, nil
}

// IDs ...
func (r *fsv) IDs(opts ...IDsOption) ([]string, error) {
	options := NewIDsOptions(opts...)
	prefix, showReserved := options.Prefix, options.Reserved

	files, err := r.checkCache()
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(files.ids))
	for _, id := range files.ids {
		if !showReserved && strings.HasPrefix(id, ReservedPrefix) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(id, prefix) {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Exists ...
func (r *fsv) Exists(id string) (bool, error) {
	files, err := r.checkCache()
	if err != nil {
		return false, err
	}
	file, ok := files.current[id]
	if !ok {
		return false, nil
	}
	if file.deleted {
		return false, nil
	}
	return true, nil
}

// Reset ...
func (r *fsv) Reset() error {
	r.Lock()
	defer r.Unlock()
	if err := os.RemoveAll(r.dir); err != nil {
		return err
	}
	r.cache = nil
	return nil
}

func (r *fsv) checkCache() (*files, error) {
	r.Lock()
	defer r.Unlock()
	cache := r.cache
	if cache != nil {
		return cache, nil
	}

	files, err := listFiles(r.dir)
	if err != nil {
		return nil, err
	}
	r.cache = files

	time.AfterFunc(time.Second*2, func() {
		r.cache = nil
	})
	return files, nil
}

type file struct {
	id      string
	version int
	ts      time.Time
	deleted bool
}

func (f file) Name() string {
	name := fmt.Sprintf("%s_%015d_%d", f.id, f.version, tsutil.Millis(f.ts))
	if f.deleted {
		name = name + "~"
	}
	return name
}

func (f file) Next(now time.Time) file {
	next := f.version + 1
	return newFile(f.id, next, now)
}

func (f file) String() string {
	return f.Name()
}

type files struct {
	versions map[string][]file
	current  map[string]file
	ids      []string
}

func listFiles(dir string) (*files, error) {
	logger.Debugf("Keyring (fsv) list: %s", dir)

	exists, err := pathExists(dir)
	if err != nil {
		return nil, err
	}
	if !exists {
		return emptyFiles(), nil
	}

	fileInfos, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := &files{
		versions: make(map[string][]file, len(fileInfos)),
		current:  make(map[string]file, len(fileInfos)),
	}
	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			continue
		}
		f, err := parseFileName(fileInfo.Name())
		if err != nil {
			// logger.Warningf("Unrecognized git file name: %s", fileInfo.Name())
			continue
		}
		// logger.Debugf("File: %s", f)

		versions, ok := files.versions[f.id]
		if !ok {
			files.versions[f.id] = []file{f}
		} else {
			files.versions[f.id] = append(versions, f)
		}
		files.current[f.id] = f
	}

	files.ids = make([]string, 0, len(files.current))
	for id, f := range files.current {
		if !f.deleted {
			files.ids = append(files.ids, id)
		}
	}
	sort.Slice(files.ids, func(i, j int) bool {
		return files.ids[i] < files.ids[j]
	})

	return files, nil
}

func parseFileName(name string) (file, error) {
	deleted := false
	if strings.HasSuffix(name, "~") {
		deleted = true
		name = name[:len(name)-1]
	}

	spl := strings.Split(name, "_")
	if len(spl) < 3 {
		return file{}, errors.Errorf("invalid git file format")
	}
	id := spl[0]
	v, err := strconv.Atoi(spl[1])
	if err != nil {
		return file{}, errors.Wrapf(err, "invalid git file format (version)")
	}
	t, err := strconv.Atoi(spl[2])
	if err != nil {
		return file{}, errors.Wrapf(err, "invalid git file format (ts)")
	}
	ts := tsutil.ParseMillis(t)

	return file{
		id:      id,
		version: v,
		ts:      ts,
		deleted: deleted,
	}, nil
}

func newFile(id string, ver int, ts time.Time) file {
	// TODO: Panic if version > max
	return file{
		id:      id,
		version: ver,
		ts:      ts,
	}
}

func emptyFiles() *files {
	return &files{
		versions: map[string][]file{},
		current:  map[string]file{},
		ids:      []string{},
	}
}
