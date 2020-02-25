package services

import (
	"net/url"

	"github.com/pkg/errors"
)

// Service describes a user service.
type Service interface {
	// Name of the service, e.g. "github", "twitter".
	Name() string

	// NormalizeUsername normalizes a user name. For example, on Twitter,
	// "@username" becomes "username".
	NormalizeUsername(string) string

	// ValidateURL validates the URL and returns an URL of where to find the
	// signed statement.
	ValidateURL(name string, u *url.URL) (*url.URL, error)

	// ValidateName validates the service user name.
	ValidateUsername(name string) error

	// CheckContent returns data with statement.
	// For Twitter, Github there is no check since the user owns the URL location.
	// For Reddit, we need to verify the listing, author and subreddit and return only the listing text.
	CheckContent(name string, b []byte) ([]byte, error)
}

// NewService returns a service by name.
func NewService(service string) (Service, error) {
	switch service {
	case Twitter.Name():
		return Twitter, nil
	case Github.Name():
		return Github, nil
	case Reddit.Name():
		return Reddit, nil
	default:
		return nil, errors.Errorf("invalid service %s", service)
	}
}
