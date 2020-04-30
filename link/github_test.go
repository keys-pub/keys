package link_test

import (
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func TestGithubValidateName(t *testing.T) {
	err := link.Github.ValidateName("Gabriel")
	require.EqualError(t, err, "name should be lowercase")

	err = link.Github.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "github name is too long, it must be less than 40 characters")
}

func TestGithubValidateURL(t *testing.T) {
	testValidateURL(t, link.Github,
		"gabriel",
		"https://gist.github.com/gabriel/abcd",
		"https://gist.github.com/gabriel/abcd")

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
