package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/user/validate"

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

func (s *github) Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error) {
	apiURL, err := validate.Github.APIURL(usr.Name, usr.URL)
	if err != nil {
		return user.StatusFailure, nil, err
	}
	headers := s.headers()
	return Request(ctx, client, apiURL, headers)
}

func (s *github) Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, *Verified, error) {
	var gist gist
	if err := json.Unmarshal(b, &gist); err != nil {
		return user.StatusContentInvalid, nil, err
	}
	gistUserName := validate.Github.NormalizeName(gist.Owner.Login)
	if gistUserName != usr.Name {
		return user.StatusContentInvalid, nil, errors.Errorf("invalid gist owner login %s", gist.Owner.Login)
	}

	for _, f := range gist.Files {
		status, statement, err := user.FindVerify(usr, []byte(f.Content), false)
		if err != nil {
			return status, nil, err
		}
		return status, &Verified{Statement: statement}, nil
	}

	return user.StatusContentInvalid, nil, errors.Errorf("no gist files")
}

func (s *github) headers() []http.Header {
	return []http.Header{{
		Name:  "Accept",
		Value: "application/vnd.github.v3+json",
	}}
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
