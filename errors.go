package keys

import (
	"fmt"

	"github.com/pkg/errors"
)

// ErrVerifyFailed if key verify failed.
var ErrVerifyFailed = errors.New("verify failed")

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
