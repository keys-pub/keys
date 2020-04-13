package docs

import (
	"sort"
	"strings"
)

// StringSet is a set of strings.
type StringSet struct {
	keysMap map[string]bool
	keys    []string
}

// NewStringSet creates StringSet.
func NewStringSet(s ...string) *StringSet {
	return newStringSet(len(s), s...)
}

// NewStringSetWithCapacity ..
func NewStringSetWithCapacity(capacity int) *StringSet {
	return newStringSet(capacity)
}

func newStringSet(capacity int, s ...string) *StringSet {
	keysMap := make(map[string]bool, capacity)
	keys := make([]string, 0, capacity)
	for _, v := range s {
		keysMap[v] = true
		keys = append(keys, v)
	}
	return &StringSet{
		keysMap: keysMap,
		keys:    keys,
	}
}

// NewStringSetSplit creates StringSet for split string.
func NewStringSetSplit(s string, delim string) *StringSet {
	strs := strings.Split(s, delim)
	if len(strs) == 1 && strs[0] == "" {
		return NewStringSet()
	}
	return NewStringSet(strs...)
}

// Contains returns true if set contains string.
func (s *StringSet) Contains(str string) bool {
	return s.keysMap[str]
}

// Add to set.
func (s *StringSet) Add(str string) {
	if s.Contains(str) {
		return
	}
	s.keysMap[str] = true
	s.keys = append(s.keys, str)
}

// AddAll to set.
func (s *StringSet) AddAll(strs []string) {
	for _, str := range strs {
		s.Add(str)
	}
}

// Remove from set.
func (s *StringSet) Remove(str string) {
	delete(s.keysMap, str)
	keys := make([]string, 0, len(s.keys))
	for _, k := range s.keys {
		if k != str {
			keys = append(keys, k)
		}
	}
	s.keys = keys
}

// Size for set.
func (s *StringSet) Size() int {
	return len(s.keys)
}

// Clear set.
func (s *StringSet) Clear() {
	s.keysMap = map[string]bool{}
	s.keys = []string{}
}

// Strings returns strings in set.
func (s *StringSet) Strings() []string {
	// Copy to prevent caller changing s.keys
	keys := make([]string, 0, len(s.keys))
	keys = append(keys, s.keys...)
	return keys
}

// Sorted returns strings in set, sorted.
func (s *StringSet) Sorted() []string {
	strs := s.Strings()
	sort.Strings(strs)
	return strs
}
