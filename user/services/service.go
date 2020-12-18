// Package services defines services capable of linking a key to a user.
package services

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/keys-pub/keys/request"
)

// Service describes a user service.
type Service interface {
	// Identifier of the service, e.g. "github", "twitter".
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

	// CheckContent checks content and returns signed statement
	// For Github there is no check since the user owns the URL location.
	// For Reddit, we need to verify the listing, author and subreddit and return only the listing text.
	CheckContent(name string, b []byte) ([]byte, error)

	// Headers to include with request (for example, an auth header).
	Headers(urs string) ([]request.Header, error)
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
