package link_test

import (
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func TestGithubNormalizeName(t *testing.T) {
	testNormalizeName(t, link.Github, "gabriel", "gabriel")
	testNormalizeName(t, link.Github, "Gabriel", "gabriel")
}

func TestGithubValidateName(t *testing.T) {
	err := link.Github.ValidateName("Gabriel")
	require.NoError(t, err)

	err = link.Github.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "github name is too long, it must be less than 40 characters")
}

func TestGithubValidateURL(t *testing.T) {
	testValidateURL(t, link.Github,
		"gabriel",
		"https://gist.github.com/gabriel/abcd",
		"https://gist.github.com/gabriel/abcd")

	testValidateURL(t, link.Github,
		"Gabriel",
		"https://gist.github.com/Gabriel/abcd",
		"https://gist.github.com/Gabriel/abcd")

	testValidateURLErr(t, link.Github,
		"gabriel",
		"https://gist.github.com/gabriel",
		"path invalid [gabriel] for url https://gist.github.com/gabriel")

	testValidateURLErr(t, link.Github,
		"gabriel",
		"https://gis.github.com/gabriel/abcd",
		"invalid host for url https://gis.github.com/gabriel/abcd")

	testValidateURLErr(t, link.Github,
		"gabriel",
		"https://gist.github.com/gabrie/abcd",
		"path invalid (name mismatch) gabrie != gabriel")
}
