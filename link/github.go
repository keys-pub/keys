package link

import (
	"net/url"
	"strings"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

type github struct{}

// Github service.
var Github = &github{}

func (s *github) Name() string {
	return "github"
}

func (s *github) NormalizeName(name string) string {
	return strings.ToLower(name)
}

func (s *github) ValidateURL(name string, u *url.URL) (*url.URL, error) {
	if u.Scheme != "https" {
		return nil, errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "gist.github.com" {
		return nil, errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 2 {
		return nil, errors.Errorf("path invalid %s for url %s", paths, u)
	}
	if strings.ToLower(paths[0]) != name {
		return nil, errors.Errorf("path invalid (name mismatch) %s != %s", paths[0], name)
	}
	return u, nil
}

func (s *github) ValidateName(name string) error {
	isASCII := encoding.IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("name has non-ASCII characters")
	}

	if len(name) > 39 {
		return errors.Errorf("github name is too long, it must be less than 40 characters")
	}

	return nil
}

func (s *github) CheckContent(name string, b []byte) ([]byte, error) {
	return b, nil
}
