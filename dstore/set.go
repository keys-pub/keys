package dstore

import (
	"sort"
	"strings"
)

// StringSet is a set of strings.
type StringSet struct {
	strsMap map[string]bool
	strs    []string
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
	strsMap := make(map[string]bool, capacity)
	strs := make([]string, 0, capacity)
	for _, v := range s {
		strsMap[v] = true
		strs = append(strs, v)
	}
	return &StringSet{
		strsMap: strsMap,
		strs:    strs,
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
	return s.strsMap[str]
}

// Add to set.
func (s *StringSet) Add(str string) {
	if s.Contains(str) {
		return
	}
	s.strsMap[str] = true
	s.strs = append(s.strs, str)
}

// AddAll to set.
func (s *StringSet) AddAll(strs []string) {
	for _, str := range strs {
		s.Add(str)
	}
}

// Remove from set.
func (s *StringSet) Remove(str string) {
	delete(s.strsMap, str)
	keys := make([]string, 0, len(s.strs))
	for _, k := range s.strs {
		if k != str {
			keys = append(keys, k)
		}
	}
	s.strs = keys
}

// Size for set.
func (s *StringSet) Size() int {
	return len(s.strs)
}

// Clear set.
func (s *StringSet) Clear() {
	s.strsMap = map[string]bool{}
	s.strs = []string{}
}

// Strings returns strings in set.
func (s *StringSet) Strings() []string {
	// Copy to prevent caller changing s.strs
	keys := make([]string, 0, len(s.strs))
	keys = append(keys, s.strs...)
	return keys
}

// Sorted returns strings in set, sorted.
func (s *StringSet) Sorted() []string {
	strs := s.Strings()
	sort.Strings(strs)
	return strs
}
