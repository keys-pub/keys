package keys

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type github struct{}

// Github service.
var Github = &github{}

func (s *github) Name() string {
	return "github"
}

func (s *github) NormalizeName(name string) string {
	return name
}

func (s *github) ValidateURL(name string, u *url.URL) error {
	if u.Scheme != "https" {
		return errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "gist.github.com" {
		return errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 2 {
		return errors.Errorf("path invalid %s for url %s", paths, u)
	}
	if paths[0] != name {
		return errors.Errorf("path invalid (name mismatch) %s != %s", paths[0], name)
	}
	return nil
}

func (s *github) ValidateName(name string) error {
	isASCII := IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("user name has non-ASCII characters")
	}
	hu := HasUpper(name)
	if hu {
		return errors.Errorf("user name should be lowercase")
	}

	if len(name) > 39 {
		return errors.Errorf("github name too long")
	}

	return nil
}
