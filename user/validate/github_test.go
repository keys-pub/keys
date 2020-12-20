package validate_test

import (
	"testing"

	"github.com/keys-pub/keys/user/validate"
	"github.com/stretchr/testify/require"
)

func TestGithubNormalizeName(t *testing.T) {
	github := validate.Github
	name := github.NormalizeName("Gabriel")
	require.Equal(t, "gabriel", name)
}

func TestGithubValidateName(t *testing.T) {
	github := validate.Github
	err := github.ValidateName("gabriel01")
	require.NoError(t, err)

	err = github.ValidateName("gabriel-01")
	require.NoError(t, err)

	err = github.ValidateName("gabriel_01")
	require.EqualError(t, err, "name has an invalid character")

	err = github.ValidateName("Gabriel")
	require.EqualError(t, err, "name has an invalid character")

	err = github.ValidateName("Gabriel++")
	require.EqualError(t, err, "name has an invalid character")

	err = github.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "github name is too long, it must be less than 40 characters")
}

func TestGithubNormalizeURL(t *testing.T) {
	github := validate.Github
	testNormalizeURL(t, github,
		"gabriel",
		"https://gist.github.com/gabriel/abcd?",
		"https://gist.github.com/gabriel/abcd")

	testNormalizeURL(t, github,
		"gabriel",
		"https://gist.github.com/Gabriel/abcd",
		"https://gist.github.com/gabriel/abcd")
}

func TestGithubValidateURL(t *testing.T) {
	github := validate.Github
	testValidateURL(t, github,
		"gabriel",
		"https://gist.github.com/gabriel/abcd")

	testValidateURLErr(t, github,
		"gabriel",
		"https://gist.github.com/gabriel",
		"path invalid [gabriel] for url https://gist.github.com/gabriel")

	testValidateURLErr(t, github,
		"gabriel",
		"https://gis.github.com/gabriel/abcd",
		"invalid host for url https://gis.github.com/gabriel/abcd")

	testValidateURLErr(t, github,
		"gabriel",
		"https://gist.github.com/gabrie/abcd",
		"path invalid (name mismatch) gabrie != gabriel")
}
