package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestNewErrNotFound(t *testing.T) {
	require.EqualError(t, keys.NewErrNotFound("123"), "not found 123")
	require.EqualError(t, keys.NewErrNotFound(""), "not found")
}
