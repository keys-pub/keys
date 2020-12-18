package services

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/keys-pub/keys/http"
	"github.com/pkg/errors"
)

// TODO Normalize spaces, check a-zA-Z0-9 instead of ASCII

type reddit struct{}

// Reddit service.
var Reddit = &reddit{}

func (s *reddit) ID() string {
	return "reddit"
}

func (s *reddit) NormalizeURL(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *reddit) ValidateURL(name string, urs string) (string, error) {
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
	var posts redditPosts

	if err := json.Unmarshal(b, &posts); err != nil {
		return nil, err
	}
	logger.Debugf("Reddit unmarshaled posts: %+v", posts)
	if len(posts) == 0 {
		return nil, errors.Errorf("no posts")
	}

	if len(posts[0].Data.Children) == 0 {
		return nil, errors.Errorf("no listing children")
	}

	author := posts[0].Data.Children[0].Data.Author
	if name != strings.ToLower(author) {
		return nil, errors.Errorf("invalid author %s", author)
	}
	subreddit := posts[0].Data.Children[0].Data.Subreddit
	if "keyspubmsgs" != subreddit {
		return nil, errors.Errorf("invalid subreddit %s", subreddit)
	}
	selftext := posts[0].Data.Children[0].Data.Selftext
	return []byte(selftext), nil
}

func (s *reddit) Request(ctx context.Context, client http.Client, urs string) ([]byte, error) {
	req, err := http.NewRequest("GET", urs, nil)
	if err != nil {
		return nil, err
	}
	headers, err := s.headers(urs)
	if err != nil {
		return nil, err
	}
	b, err := client.Request(ctx, req, headers)
	if err != nil {
		if errHTTP, ok := errors.Cause(err).(http.ErrHTTP); ok && errHTTP.StatusCode == 404 {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

func (s *reddit) headers(urs string) ([]http.Header, error) {
	ur, err := url.Parse(urs)
	if err != nil {
		return nil, err
	}
	// Not sure if this is required anymore.
	if strings.HasSuffix(ur.Host, ".reddit.com") {
		return []http.Header{
			http.Header{Name: "Host", Value: "reddit.com"},
		}, nil
	}
	return nil, nil
}

type redditPosts []struct {
	Kind string `json:"kind"`
	Data struct {
		Modhash  string `json:"modhash"`
		Dist     int    `json:"dist"`
		Children []struct {
			Kind string `json:"kind"`
			Data struct {
				Subreddit string `json:"subreddit"`
				Selftext  string `json:"selftext"`
				Author    string `json:"author"`
			} `json:"data"`
		} `json:"children"`
		After  interface{} `json:"after"`
		Before interface{} `json:"before"`
	} `json:"data"`
}
