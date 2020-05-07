package link

import (
	"net/url"
	"strings"

	"github.com/keys-pub/keys/encoding"
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
		return strings.ToLower(name[1:])
	}
	return strings.ToLower(name)
}

func (s *twitter) ValidateURL(name string, u *url.URL) (*url.URL, error) {
	if u.Scheme != "https" {
		return nil, errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "twitter.com" {
		return nil, errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 3 {
		return nil, errors.Errorf("path invalid %s for url %s", paths, u)
	}
	if strings.ToLower(paths[0]) != name {
		return nil, errors.Errorf("path invalid (name mismatch) for url %s", u)
	}
	return u, nil
}

func (s *twitter) ValidateName(name string) error {
	isASCII := encoding.IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("name has non-ASCII characters")
	}

	if len(name) > 15 {
		return errors.Errorf("twitter name is too long, it must be less than 16 characters")
	}

	return nil
}

func (s *twitter) CheckContent(name string, b []byte) ([]byte, error) {
	return b, nil
}
