package keys

import (
	"fmt"
)

// ErrNotFound describes a key not found error when a key is required.
type ErrNotFound struct {
	ID string
}

// NewErrNotFound constructs a ErrNotFound.
func NewErrNotFound(id string) error {
	return ErrNotFound{ID: id}
}

func (e ErrNotFound) Error() string {
	if e.ID == "" {
		return "not found"
	}
	return fmt.Sprintf("not found %s", e.ID)
}
