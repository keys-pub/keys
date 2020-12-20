package validate

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// TwitterID is the id for twitter.
const TwitterID = "twitter"

type twitter struct{}

// Twitter ..
var Twitter = &twitter{}

func (s *twitter) ID() string {
	return TwitterID
}

func (s *twitter) NormalizeName(name string) string {
	name = strings.ToLower(name)
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}
	return name
}

func (s *twitter) ValidateName(name string) error {
	ok := isAlphaNumericWithUnderscore(name)
	if !ok {
		return errors.Errorf("name has an invalid character")
	}

	if len(name) > 15 {
		return errors.Errorf("twitter name is too long, it must be less than 16 characters")
	}

	return nil
}

func (s *twitter) NormalizeURL(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *twitter) ValidateURL(name string, urs string) error {
	_, err := s.APIURL(name, urs)
	return err
}

func (s *twitter) APIURL(name string, urs string) (string, error) {
	u, err := url.Parse(urs)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.Errorf("invalid scheme for url %s", u)
	}
	switch u.Host {
	case "twitter.com", "mobile.twitter.com":
		// OK
	default:
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

	status := paths[2]
	return "https://api.twitter.com/2/tweets/" + status + "?expansions=author_id", nil
}
