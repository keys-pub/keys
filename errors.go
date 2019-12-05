package keys

import (
	"fmt"

	"github.com/pkg/errors"
)

// ErrNotFound describes a key not found error when a key is required.
type ErrNotFound struct {
	ID   ID
	Type string
}

// NewErrNotFound constructs a ErrNotFound.
func NewErrNotFound(id ID, typ string) error {
	return ErrNotFound{ID: id, Type: typ}
}

func (e ErrNotFound) Error() string {
	if e.ID == "" {
		return fmt.Sprintf("%s not found", TypeDescription(e.Type))
	}
	return fmt.Sprintf("%s not found %s", TypeDescription(e.Type), e.ID)
}

type tempError interface {
	Temporary() bool
}

// IsTemporaryError returns true if the error has Temporary() function and that returns true
func IsTemporaryError(err error) bool {
	switch err := errors.Cause(err).(type) {
	case tempError:
		if err.Temporary() {
			return true
		}
	}
	return false
}
