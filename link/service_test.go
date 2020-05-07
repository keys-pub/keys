package link_test

import (
	"net/url"
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func testNormalizeName(t *testing.T, service link.Service, name string, expected string) {
	require.Equal(t, service.NormalizeName(name), expected)
}

func testValidateURL(t *testing.T, service link.Service, name string, urs string, expected string) {
	ur, err := url.Parse(urs)
	require.NoError(t, err)
	urout, err := service.ValidateURL(name, ur)
	require.NoError(t, err)
	require.Equal(t, expected, urout.String())
}

func testValidateURLErr(t *testing.T, service link.Service, name string, urs string, expected string) {
	ur, err := url.Parse(urs)
	require.NoError(t, err)
	_, err = service.ValidateURL(name, ur)
	require.EqualError(t, err, expected)
}
