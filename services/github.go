package services

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

func (s *github) NormalizeUsername(name string) string {
	return name
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
	if paths[0] != name {
		return nil, errors.Errorf("path invalid (name mismatch) %s != %s", paths[0], name)
	}
	return u, nil
}

func (s *github) ValidateUsername(name string) error {
	isASCII := encoding.IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("user name has non-ASCII characters")
	}
	hu := encoding.HasUpper(name)
	if hu {
		return errors.Errorf("user name should be lowercase")
	}

	if len(name) > 39 {
		return errors.Errorf("github name too long")
	}

	return nil
}

func (s *github) CheckURLContent(name string, b []byte) error {
	return nil
}
