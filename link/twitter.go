package link

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type twitter struct{}

// Twitter service.
var Twitter = &twitter{}

func (s *twitter) ID() string {
	return "twitter"
}

func (s *twitter) NormalizeURLString(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *twitter) ValidateURLString(name string, urs string) (string, error) {
	u, err := url.Parse(urs)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "twitter.com" {
		return "", errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 3 {
		return "", errors.Errorf("path invalid %s for url %s", paths, u)
	}
	if paths[0] != name {
		return "", errors.Errorf("path invalid (name mismatch) for url %s", u)
	}
	return u.String(), nil
}

func (s *twitter) NormalizeName(name string) string {
	name = strings.ToLower(name)
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}
	return name
}

func (s *twitter) ValidateName(name string) error {
	isAlphaNumeric := isAlphaNumeric(name)
	if !isAlphaNumeric {
		return errors.Errorf("name is not lowercase alphanumeric (a-z0-9)")
	}

	if len(name) > 15 {
		return errors.Errorf("twitter name is too long, it must be less than 16 characters")
	}

	return nil
}

func (s *twitter) CheckContent(name string, b []byte) ([]byte, error) {
	return b, nil
}
