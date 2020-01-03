package keys

import (
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// Address is a list of IDs.
type Address struct {
	recipients []ID
	idmap      map[ID]bool
}

// NewAddress returns address from recipient ids.
func NewAddress(recipients ...ID) (*Address, error) {
	if len(recipients) == 0 {
		return nil, errors.Errorf("no recipients")
	}
	sort.Slice(recipients, func(i, j int) bool { return recipients[i].String() < recipients[j].String() })
	idmap := make(map[ID]bool, len(recipients))
	for _, r := range recipients {
		if ok := idmap[r]; ok {
			return nil, errors.Errorf("duplicate address %s", r)
		}
		idmap[r] = true
	}
	return &Address{
		recipients: recipients,
		idmap:      idmap,
	}, nil
}

// Recipients returns Ikeys.
func (a Address) Recipients() []ID {
	return a.recipients
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
	for _, r := range a.recipients {
		if r == id {
			return true
		}
	}
	return false
}

// RecipientStrings returns recipient IDs as strings.
func (a *Address) RecipientStrings() []string {
	s := make([]string, 0, len(a.recipients))
	for _, r := range a.recipients {
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
	return strings.Join(a.RecipientStrings(), ":")
}

// Add recipient to address
// func (a *Address) Add(recipient ID) error {
// 	if a.Contains(recipient) {
// 		return errors.Errorf("address already has recipient %s", recipient)
// 	}
// 	recipients := a.recipients
// 	recipients = append(recipients, recipient)
// 	sort.Slice(recipients, func(i, j int) bool { return recipients[i].String() < recipients[j].String() })
// 	a.recipients = recipients
// 	return nil
// }
