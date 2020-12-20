package validate_test

import (
	"testing"

	"github.com/keys-pub/keys/user/validate"
	"github.com/stretchr/testify/require"
)

func testNormalizeURL(t *testing.T, validator validate.Validator, name string, urs string, expected string) {
	out, err := validator.NormalizeURL(name, urs)
	require.NoError(t, err)
	require.Equal(t, expected, out)
}

func testValidateURL(t *testing.T, validator validate.Validator, name string, urs string) {
	err := validator.ValidateURL(name, urs)
	require.NoError(t, err)
}

func testValidateURLErr(t *testing.T, validator validate.Validator, name string, urs string, expected string) {
	err := validator.ValidateURL(name, urs)
	require.EqualError(t, err, expected)
}
