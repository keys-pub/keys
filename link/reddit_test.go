package link_test

import (
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func TestRedditNormalizeName(t *testing.T) {
	name := link.Reddit.NormalizeName("Gabriel")
	require.Equal(t, "gabriel", name)
}

func TestRedditValidateName(t *testing.T) {
	err := link.Reddit.ValidateName("gabriel01")
	require.NoError(t, err)

	err = link.Reddit.ValidateName("Gabriel")
	require.EqualError(t, err, "name is not lowercase alphanumeric (a-z0-9)")

	err = link.Reddit.ValidateName("Gabriel++")
	require.EqualError(t, err, "name is not lowercase alphanumeric (a-z0-9)")

	err = link.Reddit.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "reddit name is too long, it must be less than 21 characters")
}

func TestRedditNormalizeURL(t *testing.T) {
	testNormalizeURL(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/?",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/")

	testNormalizeURL(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/Gabrlh/",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/")
}

func TestRedditValidateURL(t *testing.T) {
	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/",
		"https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://old.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/",
		"https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/",
		"https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh?",
		"https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURL(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/?",
		"https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")

	testValidateURLErr(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/user/?",
		"invalid path /r/keyspubmsgs/comments/f8g9vd/user/")

	testValidateURLErr(t, link.Reddit,
		"gabrlh",
		"https://reddit.com/r/subreddit/comments/f8g9vd/gabrlh/?",
		"invalid path /r/subreddit/comments/f8g9vd/gabrlh/")
}
