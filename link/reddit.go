package link

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// TODO Normalize spaces, check a-zA-Z0-9 instead of ASCII

type reddit struct{}

// Reddit service.
var Reddit = &reddit{}

func (s *reddit) ID() string {
	return "reddit"
}

func (s *reddit) NormalizeURLString(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *reddit) ValidateURLString(name string, urs string) (string, error) {
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

	// URL from https://reddit.com/r/keyspubmsgs/comments/{id}/{username}/ to
	//          https://www.reddit.com/r/keyspubmsgs/comments/{id}/{username}.json

	prunedName := strings.ReplaceAll(name, "-", "")

	if len(paths) >= 5 && paths[0] == "r" && paths[1] == "keyspubmsgs" && paths[2] == "comments" && paths[4] == prunedName {
		// Request json
		ursj, err := url.Parse("https://www.reddit.com" + strings.TrimSuffix(u.Path, "/") + ".json")
		if err != nil {
			return "", err
		}
		return ursj.String(), nil
	}

	return "", errors.Errorf("invalid path %s", u.Path)
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

func (s *reddit) CheckContent(name string, b []byte) ([]byte, error) {
	type childData struct {
		Author    string `json:"author"`
		Selftext  string `json:"selftext"`
		Subreddit string `json:"subreddit"`
	}
	type child struct {
		Kind string    `json:"kind"`
		Data childData `json:"data"`
	}
	type data struct {
		Children []child `json:"children"`
	}
	type listing struct {
		Kind string `json:"kind"`
		Data data   `json:"data"`
	}

	var listings []listing

	if err := json.Unmarshal(b, &listings); err != nil {
		return nil, err
	}
	logger.Debugf("Umarshal listing: %+v", listings)
	if len(listings) == 0 {
		return nil, errors.Errorf("no listings")
	}

	if len(listings[0].Data.Children) == 0 {
		return nil, errors.Errorf("no listing children")
	}
	author := listings[0].Data.Children[0].Data.Author
	if name != strings.ToLower(author) {
		return nil, errors.Errorf("invalid author %s", author)
	}
	subreddit := listings[0].Data.Children[0].Data.Subreddit
	if "keyspubmsgs" != subreddit {
		return nil, errors.Errorf("invalid subreddit %s", subreddit)
	}
	selftext := listings[0].Data.Children[0].Data.Selftext
	return []byte(selftext), nil
}
