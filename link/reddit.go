package link

import (
	"encoding/json"
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
	switch u.Host {
	case "reddit.com", "old.reddit.com", "www.reddit.com":
		// OK
	default:
		return nil, errors.Errorf("invalid host for url %s", u)
	}
	path := u.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")

	// https://reddit.com/r/keyspubmsgs/comments/{id}/{username}/

	if len(paths) >= 5 && paths[0] == "r" && paths[1] == "keyspubmsgs" && paths[2] == "comments" && paths[4] == name {
		// Request json
		return url.Parse("https://reddit.com" + strings.TrimSuffix(u.Path, "/") + ".json")
	}

	return nil, errors.Errorf("invalid path %s", u.Path)
}

func (s *reddit) ValidateUsername(name string) error {
	isASCII := encoding.IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("user name has non-ASCII characters")
	}
	hu := encoding.HasUpper(name)
	if hu {
		return errors.Errorf("user name should be lowercase")
	}
	if len(name) > 20 {
		return errors.Errorf("reddit name too long")
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
	if name != author {
		return nil, errors.Errorf("invalid author %s", author)
	}
	subreddit := listings[0].Data.Children[0].Data.Subreddit
	if "keyspubmsgs" != subreddit {
		return nil, errors.Errorf("invalid subreddit %s", subreddit)
	}
	selftext := listings[0].Data.Children[0].Data.Selftext
	return []byte(selftext), nil
}
