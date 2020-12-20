package validate

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/pkg/errors"
)

// Validator describes a a validator for a user service.
type Validator interface {
	// Normalize the service user name.
	// For example, on Twitter, "@username" becomes "username" or "Gabriel"
	// becomes "gabriel".
	NormalizeName(name string) string

	// ValidateName validates the service user name.
	ValidateName(name string) error

	// NormalizeURL normalizes an url string.
	NormalizeURL(name string, urs string) (string, error)

	// ValidateURL validates the URL string.
	ValidateURL(name string, urs string) error
}

var services = map[string]Validator{
	"twitter": Twitter,
	"github":  Github,
	"reddit":  Reddit,
	"https":   HTTPS,
	"echo":    Echo,
}

// Lookup service by name.
func Lookup(service string) (Validator, error) {
	out, ok := services[service]
	if out == nil || !ok {
		return nil, errors.Errorf("service not found: %s", service)
	}
	return out, nil
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
