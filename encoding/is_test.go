package encoding_test

import (
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/stretchr/testify/require"
)

func TestIsASCII(t *testing.T) {
	require.True(t, encoding.IsASCII([]byte("ok")))
	require.False(t, encoding.IsASCII([]byte{0xFF}))
}

func TestIsAlphaNumeric(t *testing.T) {
	require.False(t, encoding.IsAlphaNumeric("", ""))
	require.True(t, encoding.IsAlphaNumeric("a", ""))
	require.True(t, encoding.IsAlphaNumeric("A", ""))
	require.True(t, encoding.IsAlphaNumeric("0", ""))
	require.True(t, encoding.IsAlphaNumeric("-", "-"))
	require.True(t, encoding.IsAlphaNumeric("_", "_"))
	require.True(t, encoding.IsAlphaNumeric("Abc-def", "-"))
	require.False(t, encoding.IsAlphaNumeric("Abc-def", "_"))
	require.False(t, encoding.IsAlphaNumeric(":", ""))
}

func TestHasUpper(t *testing.T) {
	require.False(t, encoding.HasUpper("ok"))
	require.True(t, encoding.HasUpper("Ok"))
}
