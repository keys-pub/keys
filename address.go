package keys

import (
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// Address is a canonical list of IDs.
type Address struct {
	ids   []ID
	idmap map[ID]bool
}

// NewAddress returns an Address from a list of IDs.
func NewAddress(ids ...ID) (*Address, error) {
	if len(ids) == 0 {
		return nil, errors.Errorf("no ids")
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	idmap := make(map[ID]bool, len(ids))
	for _, r := range ids {
		if ok := idmap[r]; ok {
			return nil, errors.Errorf("duplicate address %s", r)
		}
		idmap[r] = true
	}
	return &Address{
		ids:   ids,
		idmap: idmap,
	}, nil
}

// ParseAddress returns address from a string.
func ParseAddress(saddrs ...string) (*Address, error) {
	if len(saddrs) == 0 {
		return nil, errors.Errorf("no addresses to parse")
	}
	ids := []ID{}
	for _, saddr := range saddrs {
		recs := strings.Split(saddr, ":")
		for _, r := range recs {
			id, err := ParseID(r)
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
	}
	return NewAddress(ids...)
}

// Contains returns true if address contains the specified id.
func (a *Address) Contains(id ID) bool {
	for _, r := range a.ids {
		if r == id {
			return true
		}
	}
	return false
}

// Strings returns IDs as strings.
func (a *Address) Strings() []string {
	s := make([]string, 0, len(a.ids))
	for _, r := range a.ids {
		s = append(s, r.String())
	}
	return s
}

// String returns a canonical string representation of an address.
// The first address part is less than the second part.
//
//     NewAddress("bob", "alice").String() => "alice:bob"
//
func (a *Address) String() string {
	return strings.Join(a.Strings(), ":")
}
