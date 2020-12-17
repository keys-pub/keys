package link

import (
	"net/url"
	"strings"

	"github.com/keys-pub/keys/request"
	"github.com/pkg/errors"
)

// GithubID is id for github.
const GithubID = "github"

type github struct{}

// NewGithub service.
func NewGithub() Service {
	return &github{}
}

func (s *github) ID() string {
	return GithubID
}

func (s *github) NormalizeURLString(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *github) ValidateURLString(name string, urs string) (string, error) {
	u, err := url.Parse(urs)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "gist.github.com" {
		return "", errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 2 {
		return "", errors.Errorf("path invalid %s for url %s", paths, u)
	}
	if paths[0] != name {
		return "", errors.Errorf("path invalid (name mismatch) %s != %s", paths[0], name)
	}
	return u.String(), nil
}

func (s *github) NormalizeName(name string) string {
	name = strings.ToLower(name)
	return name
}

func (s *github) ValidateName(name string) error {
	ok := isAlphaNumericWithDash(name)
	if !ok {
		return errors.Errorf("name has an invalid character")
	}

	if len(name) > 39 {
		return errors.Errorf("github name is too long, it must be less than 40 characters")
	}

	return nil
}

func (s *github) CheckContent(name string, b []byte) ([]byte, error) {
	return b, nil
}

func (s *github) Headers(ur *url.URL) ([]request.Header, error) {
	return nil, nil
}
