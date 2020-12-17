package services_test

import (
	"testing"

	"github.com/keys-pub/keys/user/services"
	"github.com/stretchr/testify/require"
)

func testNormalizeURL(t *testing.T, service services.Service, name string, urs string, expected string) {
	out, err := service.NormalizeURLString(name, urs)
	require.NoError(t, err)
	require.Equal(t, expected, out)
}

func testValidateURL(t *testing.T, service services.Service, name string, urs string, expected string) {
	urout, err := service.ValidateURLString(name, urs)
	require.NoError(t, err)
	require.Equal(t, expected, urout)
}

func testValidateURLErr(t *testing.T, service services.Service, name string, urs string, expected string) {
	_, err := service.ValidateURLString(name, urs)
	require.EqualError(t, err, expected)
}
