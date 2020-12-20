// Package services defines services capable of linking a key to a user.
package services

import (
	"context"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
)

// Response from service request.
type Response struct {
	Status    user.Status
	Statement string
}

// Service describes a user service.
type Service interface {
	// Request resource with client.
	Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error)

	// Verify content.
	Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, string, error)
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
