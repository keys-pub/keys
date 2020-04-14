package util

import "github.com/pkg/errors"

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
