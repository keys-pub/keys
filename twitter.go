package keys

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type twitter struct{}

// Twitter service.
var Twitter = &twitter{}

func (s *twitter) Name() string {
	return "twitter"
}

func (s *twitter) NormalizeName(name string) string {
	if len(name) > 0 && name[0] == '@' {
		return name[1:]
	}
	return name
}

func (s *twitter) ValidateURL(name string, u *url.URL) error {
	if u.Scheme != "https" {
		return errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "twitter.com" {
		return errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 3 {
		return errors.Errorf("path invalid %s for url %s", paths, u)
	}
	if paths[0] != name {
		return errors.Errorf("path invalid (name mismatch) for url %s", u)
	}
	return nil
}

func (s *twitter) ValidateName(name string) error {
	isASCII := IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("user name has non-ASCII characters")
	}
	hu := HasUpper(name)
	if hu {
		return errors.Errorf("user name should be lowercase")
	}

	if len(name) > 15 {
		return errors.Errorf("twitter name too long")
	}

	return nil
}
