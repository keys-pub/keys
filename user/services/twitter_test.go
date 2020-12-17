package services_test

import (
	"testing"

	"github.com/keys-pub/keys/user/services"
	"github.com/stretchr/testify/require"
)

func TestTwitterNormalizeName(t *testing.T) {
	twitter := services.NewTwitter("")
	name := twitter.NormalizeName("Gabriel")
	require.Equal(t, "gabriel", name)
}

func TestTwitterValidateName(t *testing.T) {
	twitter := services.NewTwitter("")
	err := twitter.ValidateName("gabriel01")
	require.NoError(t, err)

	err = twitter.ValidateName("gabriel_01")
	require.NoError(t, err)

	err = twitter.ValidateName("gabriel-01")
	require.EqualError(t, err, "name has an invalid character")

	err = twitter.ValidateName("Gabriel")
	require.EqualError(t, err, "name has an invalid character")

	err = twitter.ValidateName("Gabriel++")
	require.EqualError(t, err, "name has an invalid character")

	err = twitter.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "twitter name is too long, it must be less than 16 characters")
}

func TestTwitterNormalizeURL(t *testing.T) {
	twitter := services.NewTwitter("")
	testNormalizeURL(t, twitter,
		"boboloblaw",
		"https://twitter.com/Boboloblaw/status/1250914920146669568?",
		"https://twitter.com/boboloblaw/status/1250914920146669568")

	testNormalizeURL(t, twitter,
		"boboloblaw",
		"https://twitter.com/Boboloblaw/status/1250914920146669568?",
		"https://twitter.com/boboloblaw/status/1250914920146669568")
}

func TestTwitterValidateURL(t *testing.T) {
	twitter := services.NewTwitter("")
	testValidateURL(t, twitter,
		"boboloblaw",
		"https://twitter.com/boboloblaw/status/1250914920146669568",
		"https://api.twitter.com/2/tweets/1250914920146669568?expansions=author_id")

	testValidateURLErr(t, twitter,
		"boboloblaw",
		"https://twitter.com/bobolobla/status/1250914920146669568",
		"path invalid (name mismatch) for url https://twitter.com/bobolobla/status/1250914920146669568")

	testValidateURLErr(t, twitter,
		"boboloblaw",
		"https://twittter.com/boboloblaw/status/1250914920146669568",
		"invalid host for url https://twittter.com/boboloblaw/status/1250914920146669568")

	testValidateURLErr(t, twitter,
		"boboloblaw",
		"https://twitter.com/boboloblaw/status",
		"path invalid [boboloblaw status] for url https://twitter.com/boboloblaw/status")
}
