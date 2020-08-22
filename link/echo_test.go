package link_test

import (
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func TestEchoNormalizeName(t *testing.T) {
	name := link.Echo.NormalizeName("Gabriel")
	require.Equal(t, "gabriel", name)
}

func TestEchoValidateName(t *testing.T) {
	err := link.Echo.ValidateName("gabriel01")
	require.NoError(t, err)

	err = link.Echo.ValidateName("gabriel-01")
	require.NoError(t, err)

	err = link.Echo.ValidateName("gabriel_01")
	require.NoError(t, err)

	err = link.Echo.ValidateName("Gabriel")
	require.EqualError(t, err, "name has an invalid character")

	err = link.Echo.ValidateName("Gabriel++")
	require.EqualError(t, err, "name has an invalid character")

	err = link.Echo.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "test name is too long, it must be less than 40 characters")
}

func TestEchoNormalizeURL(t *testing.T) {
	testNormalizeURL(t, link.Echo,
		"gabriel",
		"test://echo/gabriel?",
		"test://echo/gabriel")
}

func TestEchoValidateURL(t *testing.T) {
	testValidateURL(t, link.Echo,
		"gabriel",
		"test://echo/gabriel",
		"test://echo/gabriel")

	testValidateURLErr(t, link.Echo,
		"gabriel",
		"test://ech/gabriel",
		"invalid host for url test://ech/gabriel")

	testValidateURLErr(t, link.Echo,
		"gabriel",
		"test://echo/gabrie",
		"path invalid (name mismatch) gabrie != gabriel")
}
