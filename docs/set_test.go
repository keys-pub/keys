package docs_test

import (
	"testing"

	"github.com/keys-pub/keys/docs"
	"github.com/stretchr/testify/require"
)

func TestStringSet(t *testing.T) {
	s := docs.NewStringSet("a", "b", "c")
	require.True(t, s.Contains("a"))
	require.False(t, s.Contains("z"))
	s.Add("z")
	require.True(t, s.Contains("z"))
	s.Add("z")
	require.Equal(t, 4, s.Size())
	s.AddAll([]string{"m", "n"})

	expected := []string{"a", "b", "c", "z", "m", "n"}
	require.Equal(t, expected, s.Strings())

	s.Clear()
	require.False(t, s.Contains("a"))
	require.False(t, s.Contains("z"))
	require.Equal(t, 0, s.Size())
}

func TestStringSetSplit(t *testing.T) {
	s := docs.NewStringSetSplit("a,b,c", ",")
	require.Equal(t, 3, s.Size())
	require.True(t, s.Contains("a"))

	s = docs.NewStringSetSplit("a", ",")
	require.Equal(t, 1, s.Size())
	require.True(t, s.Contains("a"))

	s = docs.NewStringSetSplit("", ",")
	require.Equal(t, 0, s.Size())
}
