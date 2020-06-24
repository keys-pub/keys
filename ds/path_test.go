package ds_test

import (
	"testing"

	"github.com/keys-pub/keys/ds"
	"github.com/stretchr/testify/require"
)

func TestPath(t *testing.T) {
	require.Equal(t, "/a/b", ds.Path("a", "b"))
	require.Equal(t, "/a/b/1", ds.Path("a", "b", 1))
	require.Equal(t, "/a", ds.Path("", "a"))
	require.Equal(t, "/a", ds.Path("a", ""))

	require.Equal(t, "/", ds.Path(""))
	require.Equal(t, "/", ds.Path("/"))
	require.Equal(t, "/a", ds.Path("a"))
	require.Equal(t, "/a", ds.Path("/a"))
	require.Equal(t, "/a", ds.Path("/a/"))
	require.Equal(t, "/a/b", ds.Path("/a//b/"))
}

func TestPathComponents(t *testing.T) {
	require.Equal(t, []string{"test", "sub"}, ds.PathComponents("/test//sub/"))
	require.Equal(t, []string{}, ds.PathComponents("/"))

	require.Equal(t, "", ds.PathLast(""))
	require.Equal(t, "", ds.PathLast("/"))
	require.Equal(t, "a", ds.PathLast("/a"))
	require.Equal(t, "b", ds.PathLast("/a/b"))

	require.Equal(t, "", ds.PathFirst(""))
	require.Equal(t, "", ds.PathFirst("/"))
	require.Equal(t, "a", ds.PathFirst("/a"))
	require.Equal(t, "a", ds.PathFirst("/a/b"))

	require.Equal(t, "/a", ds.PathFrom("/a", 1))
	require.Equal(t, "/b", ds.PathFrom("/a/b", 1))
	require.Equal(t, "/b/c", ds.PathFrom("/a/b/c", 1))
	require.Equal(t, "/c", ds.PathFrom("/a/b/c", 2))
}

type obj struct {
	S string
}

func (o obj) String() string {
	return o.S
}

func TestPathValues(t *testing.T) {
	require.Equal(t, "/o/abc", ds.Path("o", &obj{S: "abc"}))
}
