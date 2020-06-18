// Package keyring provides a cross-platform secure keyring.
package keyring

import "github.com/pkg/errors"

// NewSystem creates system store.
func NewSystem(service string) (Store, error) {
	if service == "" {
		return nil, errors.Errorf("invalid service")
	}
	return newSystem(service), nil
}
