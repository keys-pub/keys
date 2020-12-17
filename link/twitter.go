package link

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/keys-pub/keys/request"
	"github.com/pkg/errors"
)

// TwitterID is the id for twitter.
const TwitterID = "twitter"

type twitter struct {
	bearerToken string
}

// NewTwitter twitter service.
func NewTwitter(bearerToken string) Service {
	return &twitter{bearerToken: bearerToken}
}

func (s *twitter) ID() string {
	return TwitterID
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

func (s *twitter) Headers(ur *url.URL) ([]request.Header, error) {
	if s.bearerToken == "" {
		return nil, nil
	}
	return []request.Header{
		request.Header{
			Name:  "Authorization",
			Value: fmt.Sprintf("Bearer %s", s.bearerToken),
		},
	}, nil
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

func (s *twitter) CheckContent(name string, b []byte) ([]byte, error) {
	var tweet tweet
	if err := json.Unmarshal(b, &tweet); err != nil {
		return nil, err
	}
	logger.Debugf("Twitter unmarshaled tweet: %+v", tweet)

	// TODO: Double check tweet it matches

	found := false
	authorID := tweet.Data.AuthorID
	for _, user := range tweet.Includes.Users {
		if authorID == user.ID {
			if user.Username != name {
				return nil, errors.Errorf("invalid tweet username %s", user.Username)
			}
			found = true
		}
	}
	if !found {
		return nil, errors.Errorf("tweet username not found")
	}

	return []byte(tweet.Data.Text), nil
}

type tweet struct {
	Data struct {
		ID       string `json:"id"`
		Text     string `json:"text"`
		AuthorID string `json:"author_id"`
	} `json:"data"`
	Includes struct {
		Users []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"users"`
	} `json:"includes"`
}
