// Package services defines services capable of linking a key to a user.
package services

import (
	"context"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
)

// Verified results.
type Verified struct {
	Statement string
	Timestamp int64
	Proxied   bool
}

// Service describes a user service.
type Service interface {
	// Request resource with client.
	Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error)

	// Verify content.
	Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, *Verified, error)
}

var services = map[string]Service{
	"twitter": Twitter,
	"github":  Github,
	"reddit":  Reddit,
	"https":   HTTPS,
	"echo":    Echo,
}

// Lookup service by name.
func Lookup(service string) (Service, error) {
	out, ok := services[service]
	if out == nil || !ok {
		return nil, errors.Errorf("service not found: %s", service)
	}
	return out, nil
}
