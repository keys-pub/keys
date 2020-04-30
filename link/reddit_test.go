package link_test

import (
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func TestRedditValidateName(t *testing.T) {
	err := link.Github.ValidateName("Gabriel")
	require.EqualError(t, err, "name should be lowercase")

	err = link.Reddit.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "reddit name is too long, it must be less than 21 characters")
}

func TestRedditValidateURL(t *testing.T) {
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
