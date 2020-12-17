package services_test

import (
	"testing"

	"github.com/keys-pub/keys/user/services"
	"github.com/stretchr/testify/require"
)

func TestEchoNormalizeName(t *testing.T) {
	echo := services.NewEcho()
	name := echo.NormalizeName("Gabriel")
	require.Equal(t, "gabriel", name)
}

func TestEchoValidateName(t *testing.T) {
	echo := services.NewEcho()
	err := echo.ValidateName("gabriel01")
	require.NoError(t, err)

	err = echo.ValidateName("gabriel-01")
	require.NoError(t, err)

	err = echo.ValidateName("gabriel_01")
	require.NoError(t, err)

	err = echo.ValidateName("Gabriel")
	require.EqualError(t, err, "name has an invalid character")

	err = echo.ValidateName("Gabriel++")
	require.EqualError(t, err, "name has an invalid character")

	err = echo.ValidateName("reallylongnamereallylongnamereallylongnamereallylongnamereallylongnamereallylongname")
	require.EqualError(t, err, "test name is too long, it must be less than 40 characters")
}

func TestEchoNormalizeURL(t *testing.T) {
	echo := services.NewEcho()
	testNormalizeURL(t, echo,
		"gabriel",
		"test://echo/gabriel?",
		"test://echo/gabriel")
}

func TestEchoValidateURL(t *testing.T) {
	echo := services.NewEcho()
	testValidateURL(t, echo,
		"gabriel",
		"test://echo/gabriel",
		"test://echo/gabriel")

	testValidateURLErr(t, echo,
		"gabriel",
		"test://ech/gabriel",
		"invalid host for url test://ech/gabriel")

	testValidateURLErr(t, echo,
		"gabriel",
		"test://echo/gabrie",
		"path invalid (name mismatch) gabrie != gabriel")
}
