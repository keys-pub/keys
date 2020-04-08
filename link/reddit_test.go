package link_test

import (
	"net/url"
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func testValidateURL(t *testing.T, service link.Service, name string, urs string, expected string) {
	ur, err := url.Parse(urs)
	require.NoError(t, err)
	urout, err := service.ValidateURL(name, ur)
	require.NoError(t, err)
	require.Equal(t, expected, urout.String())
}

func testValidateURLErr(t *testing.T, service link.Service, name string, urs string, expected string) {
	ur, err := url.Parse(urs)
	require.NoError(t, err)
	_, err = service.ValidateURL(name, ur)
	require.EqualError(t, err, expected)
}

func TestValidateURL(t *testing.T) {
	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://old.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh?",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/?",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURLErr(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/user/?",
		"invalid path /r/keyspubmsgs/comments/f8g9vd/user/")

	testValidateURLErr(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/subreddit/comments/f8g9vd/gabrlh/?",
		"invalid path /r/subreddit/comments/f8g9vd/gabrlh/")
}
