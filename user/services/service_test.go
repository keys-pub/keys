package services_test

import (
	"testing"

	"github.com/keys-pub/keys/user/services"
	"github.com/stretchr/testify/require"
)

func testNormalizeURL(t *testing.T, service services.Service, name string, urs string, expected string) {
	out, err := service.NormalizeURL(name, urs)
	require.NoError(t, err)
	require.Equal(t, expected, out)
}

func testValidateURL(t *testing.T, service services.Service, name string, urs string, expected string) {
	urout, err := service.ValidateURL(name, urs)
	require.NoError(t, err)
	require.Equal(t, expected, urout)
}

func testValidateURLErr(t *testing.T, service services.Service, name string, urs string, expected string) {
	_, err := service.ValidateURL(name, urs)
	require.EqualError(t, err, expected)
}
