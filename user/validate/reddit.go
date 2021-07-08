package validate

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type reddit struct{}

// Reddit service.
var Reddit = &reddit{}

func (s *reddit) ID() string {
	return "reddit"
}

func (s *reddit) NormalizeName(name string) string {
	name = strings.ToLower(name)
	return name
}

func (s *reddit) ValidateName(name string) error {
	ok := isAlphaNumericWithDashUnderscore(name)
	if !ok {
		return errors.Errorf("name has an invalid character")
	}
	if len(name) > 20 {
		return errors.Errorf("reddit name is too long, it must be less than 21 characters")
	}
	return nil
}

func (s *reddit) NormalizeURL(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *reddit) ValidateURL(name string, urs string) error {
	_, err := s.APIURL(name, urs)
	return err
}

func (s *reddit) APIURL(name string, urs string) (string, error) {
	u, err := url.Parse(urs)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.Errorf("invalid scheme for url %s", u)
	}
	switch u.Host {
	case "reddit.com", "old.reddit.com", "www.reddit.com":
		// OK
	default:
		return "", errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")

	// URL from https://reddit.com/user/{username}/comments/{id}/{post}

	prunedName := strings.ReplaceAll(name, "-", "")

	if len(paths) >= 5 && paths[0] == "user" && paths[1] == prunedName && paths[2] == "comments" {
		// Request json
		ursj, err := url.Parse("https://www.reddit.com" + strings.TrimSuffix(u.Path, "/") + ".json")
		if err != nil {
			return "", err
		}
		return ursj.String(), nil
	}

	return "", errors.Errorf("invalid path %s", u.Path)
}
