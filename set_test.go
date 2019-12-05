package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringSet(t *testing.T) {
	s := NewStringSet("a", "b", "c")
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
	s := NewStringSetSplit("a,b,c", ",")
	require.Equal(t, 3, s.Size())
	require.True(t, s.Contains("a"))

	s = NewStringSetSplit("a", ",")
	require.Equal(t, 1, s.Size())
	require.True(t, s.Contains("a"))

	s = NewStringSetSplit("", ",")
	require.Equal(t, 0, s.Size())
}

func TestIDSet(t *testing.T) {
	s := NewIDSet(ID("a"), ID("b"), ID("c"))
	require.True(t, s.Contains(ID("a")))
	require.False(t, s.Contains(ID("z")))
	s.Add("z")
	require.True(t, s.Contains(ID("z")))
	s.Add("z")
	require.Equal(t, 4, s.Size())
	s.AddAll([]ID{"m", "n"})

	expected := []ID{ID("a"), ID("b"), ID("c"), ID("z"), ID("m"), ID("n")}
	require.Equal(t, expected, s.IDs())

	s.Clear()
	require.False(t, s.Contains(ID("a")))
	require.False(t, s.Contains(ID("z")))
	require.Equal(t, 0, s.Size())
}
