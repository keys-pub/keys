package link_test

import (
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func TestTwitterValidateName(t *testing.T) {
	err := link.Twitter.ValidateName("Gabriel")
	require.EqualError(t, err, "name should be lowercase")

	err = link.Twitter.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "twitter name is too long, it must be less than 16 characters")
}

func TestTwitterValidateURL(t *testing.T) {
	testValidateURL(t, link.Twitter,
		"boboloblaw",
		"https://twitter.com/boboloblaw/status/1250914920146669568",
		"https://twitter.com/boboloblaw/status/1250914920146669568")

	testValidateURLErr(t, link.Twitter,
		"boboloblaw",
		"https://twitter.com/bobolobla/status/1250914920146669568",
		"path invalid (name mismatch) for url https://twitter.com/bobolobla/status/1250914920146669568")

	testValidateURLErr(t, link.Twitter,
		"boboloblaw",
		"https://twittter.com/boboloblaw/status/1250914920146669568",
		"invalid host for url https://twittter.com/boboloblaw/status/1250914920146669568")

	testValidateURLErr(t, link.Twitter,
		"boboloblaw",
		"https://twitter.com/boboloblaw/status",
		"path invalid [boboloblaw status] for url https://twitter.com/boboloblaw/status")
}
