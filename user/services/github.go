package services

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/keys-pub/keys/http"

	"github.com/pkg/errors"
)

// GithubID is id for github.
const GithubID = "github"

type github struct{}

// Github service.
var Github = &github{}

func (s *github) ID() string {
	return GithubID
}

func (s *github) NormalizeURL(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *github) ValidateURL(name string, urs string) (string, error) {
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
	id := paths[1]

	api := "https://api.github.com/gists/" + id
	return api, nil
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
	var gist gist
	if err := json.Unmarshal(b, &gist); err != nil {
		return nil, err
	}

	if gist.Owner.Login != name {
		return nil, errors.Errorf("invalid gist owner login %s", gist.Owner.Login)
	}

	for _, f := range gist.Files {
		return []byte(f.Content), nil
	}

	return nil, errors.Errorf("no gist files")
}

func (s *github) Request(ctx context.Context, client http.Client, urs string) ([]byte, error) {
	req, err := http.NewRequest("GET", urs, nil)
	if err != nil {
		return nil, err
	}
	b, err := client.Request(ctx, req, s.headers())
	if err != nil {
		if errHTTP, ok := errors.Cause(err).(http.Error); ok && errHTTP.StatusCode == 404 {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

func (s *github) headers() []http.Header {
	return []http.Header{
		http.Header{
			Name:  "Accept",
			Value: "application/vnd.github.v3+json",
		},
	}
}

type file struct {
	Filename  string `json:"filename"`
	Type      string `json:"type"`
	Language  string `json:"language"`
	RawURL    string `json:"raw_url"`
	Size      int    `json:"size"`
	Truncated bool   `json:"truncated"`
	Content   string `json:"content"`
}

type gist struct {
	ID        string           `json:"id"`
	Files     map[string]*file `json:"files"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
	Owner     struct {
		Login      string `json:"login"`
		ID         int    `json:"id"`
		AvatarURL  string `json:"avatar_url"`
		GravatarID string `json:"gravatar_id"`
		URL        string `json:"url"`
	} `json:"owner"`
}
