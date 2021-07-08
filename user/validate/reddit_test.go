package validate_test

import (
	"testing"

	"github.com/keys-pub/keys/user/validate"
	"github.com/stretchr/testify/require"
)

func TestRedditNormalizeName(t *testing.T) {
	reddit := validate.Reddit
	name := reddit.NormalizeName("Gabriel")
	require.Equal(t, "gabriel", name)
}

func TestRedditValidateName(t *testing.T) {
	reddit := validate.Reddit
	err := reddit.ValidateName("gabriel01")
	require.NoError(t, err)

	err = reddit.ValidateName("gabriel_01-")
	require.NoError(t, err)

	err = reddit.ValidateName("Gabriel")
	require.EqualError(t, err, "name has an invalid character")

	err = reddit.ValidateName("Gabriel++")
	require.EqualError(t, err, "name has an invalid character")

	err = reddit.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "reddit name is too long, it must be less than 21 characters")
}

func TestRedditNormalizeURL(t *testing.T) {
	reddit := validate.Reddit
	testNormalizeURL(t, reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/?",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/")

	testNormalizeURL(t, reddit,
		"gabrlh",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/Gabrlh/",
		"https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh/")
}

func TestRedditValidateURL(t *testing.T) {
	reddit := validate.Reddit
	testValidateURL(t, reddit,
		"gabrlh",
		"https://www.reddit.com/user/gabrlh/comments/f8g9vd/keyspub/")

	testValidateURL(t, reddit,
		"keys-pub",
		"https://www.reddit.com/user/keyspub/comments/f8g9vd/keyspub/")

	testValidateURL(t, reddit,
		"gabrlh",
		"https://old.reddit.com/user/gabrlh/comments/f8g9vd/keyspub/")

	testValidateURL(t, reddit,
		"gabrlh",
		"https://reddit.com/user/gabrlh/comments/f8g9vd/keyspub/")

	testValidateURL(t, reddit,
		"gabrlh",
		"https://reddit.com/user/gabrlh/comments/f8g9vd/keyspub?")

	testValidateURL(t, reddit,
		"gabrlh",
		"https://reddit.com/user/gabrlh/comments/f8g9vd/keyspub/?")

	testValidateURLErr(t, reddit,
		"gabrlh",
		"https://reddit.com/user/user/comments/f8g9vd/keyspub/?",
		"invalid path /user/user/comments/f8g9vd/keyspub/")

	testValidateURLErr(t, reddit,
		"gabrlh",
		"https://reddit.com/user/subreddit/comments/f8g9vd/keyspub/?",
		"invalid path /user/subreddit/comments/f8g9vd/keyspub/")
}
