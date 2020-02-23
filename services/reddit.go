package services

import (
	"net/url"
	"strings"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

type reddit struct{}

// Reddit service.
var Reddit = &reddit{}

func (s *reddit) Name() string {
	return "reddit"
}

func (s *reddit) NormalizeUsername(name string) string {
	return name
}

func (s *reddit) ValidateURL(name string, u *url.URL) (*url.URL, error) {
	if u.Scheme != "https" {
		return nil, errors.Errorf("invalid scheme for url %s", u)
	}
	if u.Host != "reddit.com" {
		return nil, errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")

	// https://www.reddit.com/r/keyspubmsgs/comments/{id}/{txt}/
	if len(paths) > 2 && paths[0] == "r" && paths[1] == "keyspubmsgs" {
		// Use json extension
		return url.Parse(u.String() + ".json")
	}

	return nil, errors.Errorf("invalid path %s", u.Path)
}

func (s *reddit) ValidateUsername(name string) error {
	isASCII := encoding.IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("user name has non-ASCII characters")
	}
	if len(name) > 20 {
		return errors.Errorf("reddit name too long")
	}
	return nil
}

func (s *reddit) CheckURLContent(name string, b []byte) error {
	// TODO
	return errors.Errorf("not implemented")
}
