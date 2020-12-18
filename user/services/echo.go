package services

import (
	"context"
	"net/url"
	"strings"

	"github.com/keys-pub/keys/http"
	"github.com/pkg/errors"
)

type echo struct{}

// Echo service.
var Echo = &echo{}

func (s *echo) ID() string {
	return "echo"
}

func (s *echo) NormalizeURL(name string, urs string) (string, error) {
	return basicURLString(urs)
}

func (s *echo) ValidateURL(name string, urs string) (string, error) {
	u, err := url.Parse(urs)
	if err != nil {
		return "", err
	}
	if u.Scheme != "test" {
		return "", errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "echo" {
		return "", errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) == 0 {
		return "", errors.Errorf("path invalid %s for url %s", paths, u)
	}
	if paths[0] != name {
		return "", errors.Errorf("path invalid (name mismatch) %s != %s", paths[0], name)
	}
	return u.String(), nil
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

func (s *echo) Request(ctx context.Context, client http.Client, urs string) ([]byte, error) {
	ur, err := url.Parse(urs)
	if err != nil {
		return nil, err
	}
	if ur.Scheme != "test" {
		return nil, errors.Errorf("invalid scheme for echo")
	}
	if ur.Host != "echo" {
		return nil, errors.Errorf("invalid host for echo")
	}

	path := ur.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 3 {
		return nil, errors.Errorf("path invalid %s", path)
	}
	msg, err := url.QueryUnescape(paths[2])
	if err != nil {
		return nil, err
	}
	return []byte(msg), nil
}

func (s *echo) CheckContent(name string, b []byte) ([]byte, error) {
	return b, nil
}
