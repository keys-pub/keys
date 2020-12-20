package validate

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type echo struct{}

// Echo service.
var Echo = &echo{}

func (s *echo) ID() string {
	return "echo"
}

func (s *echo) NormalizeName(name string) string {
	name = strings.ToLower(name)
	return name
}

func (s *echo) ValidateName(name string) error {
	ok := isAlphaNumericWithDashUnderscore(name)
	if !ok {
		return errors.Errorf("name has an invalid character")
	}

	if len(name) > 39 {
		return errors.Errorf("test name is too long, it must be less than 40 characters")
	}

	return nil
}

func (s *echo) NormalizeURL(name string, urs string) (string, error) {
	return basicURLString(urs)
}

func (s *echo) ValidateURL(name string, urs string) error {
	u, err := url.Parse(urs)
	if err != nil {
		return err
	}
	if u.Scheme != "test" {
		return errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "echo" {
		return errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) == 0 {
		return errors.Errorf("path invalid %s for url %s", paths, u)
	}
	if paths[0] != name {
		return errors.Errorf("path invalid (name mismatch) %s != %s", paths[0], name)
	}
	return nil
}
