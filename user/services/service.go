// Package services defines services capable of linking a key to a user.
package services

import (
	"context"
	"fmt"
	"net/url"
	"regexp"

	"github.com/keys-pub/keys/http"
	"github.com/pkg/errors"
)

// Service describes a user service.
type Service interface {
	// Identifier of the service, e.g. "github", "twitter", "reddit", "https", etc.
	ID() string

	// Normalize the service user name.
	// For example, on Twitter, "@username" becomes "username" or "Gabriel"
	// becomes "gabriel".
	NormalizeName(name string) string

	// ValidateName validates the service user name.
	ValidateName(name string) error

	// NormalizeURL normalizes an url string.
	NormalizeURL(name string, urs string) (string, error)

	// ValidateURL validates the URL string and returns where to find the
	// signed statement.
	// For example, on reddit ".json" is appended.
	ValidateURL(name string, urs string) (string, error)

	// Request resource with client.
	Request(ctx context.Context, client http.Client, urs string) ([]byte, error)

	// CheckContent checks content and returns signed statement.
	CheckContent(name string, b []byte) ([]byte, error)
}

// Lookup service by name.
func Lookup(service string) (Service, error) {
	switch service {
	case Twitter.ID():
		return Twitter, nil
	case Github.ID():
		return Github, nil
	case Reddit.ID():
		return Reddit, nil
	case HTTPS.ID():
		return HTTPS, nil
	case Echo.ID():
		return Echo, nil
	default:
		return nil, errors.Errorf("service not found: %s", service)
	}
}

var regAlphaNumericWithDash = regexp.MustCompile(`^[a-z0-9-]+$`)
var regAlphaNumericWithUnderscore = regexp.MustCompile(`^[a-z0-9_]+$`)
var regAlphaNumericWithDashUnderscore = regexp.MustCompile(`^[a-z0-9-_]+$`)

func isAlphaNumericWithDash(s string) bool {
	return regAlphaNumericWithDash.MatchString(s)
}

func isAlphaNumericWithUnderscore(s string) bool {
	return regAlphaNumericWithUnderscore.MatchString(s)
}

func isAlphaNumericWithDashUnderscore(s string) bool {
	return regAlphaNumericWithDashUnderscore.MatchString(s)
}

func basicURLString(urs string) (string, error) {
	ur, err := url.Parse(urs)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s://%s%s", ur.Scheme, ur.Host, ur.Path), nil
}
