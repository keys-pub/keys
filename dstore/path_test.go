package dstore_test

import (
	"testing"

	"github.com/keys-pub/keys/dstore"
	"github.com/stretchr/testify/require"
)

func TestPath(t *testing.T) {
	require.Equal(t, "/a/b", dstore.Path("a", "b"))
	require.Equal(t, "/a/b/1", dstore.Path("a", "b", 1))
	require.Equal(t, "/a", dstore.Path("", "a"))
	require.Equal(t, "/a", dstore.Path("a", ""))

	require.Equal(t, "/", dstore.Path(""))
	require.Equal(t, "/", dstore.Path("/"))
	require.Equal(t, "/a", dstore.Path("a"))
	require.Equal(t, "/a", dstore.Path("/a"))
	require.Equal(t, "/a", dstore.Path("/a/"))
	require.Equal(t, "/a/b", dstore.Path("/a//b/"))
}

func TestPathComponents(t *testing.T) {
	require.Equal(t, []string{"test", "sub"}, dstore.PathComponents("/test//sub/"))
	require.Equal(t, []string{}, dstore.PathComponents("/"))

	require.Equal(t, "", dstore.PathLast(""))
	require.Equal(t, "", dstore.PathLast("/"))
	require.Equal(t, "a", dstore.PathLast("/a"))
	require.Equal(t, "b", dstore.PathLast("/a/b"))

	require.Equal(t, "", dstore.PathFirst(""))
	require.Equal(t, "", dstore.PathFirst("/"))
	require.Equal(t, "a", dstore.PathFirst("/a"))
	require.Equal(t, "a", dstore.PathFirst("/a/b"))

	require.Equal(t, "/a", dstore.PathFrom("/a", 1))
	require.Equal(t, "/b", dstore.PathFrom("/a/b", 1))
	require.Equal(t, "/b/c", dstore.PathFrom("/a/b/c", 1))
	require.Equal(t, "/c", dstore.PathFrom("/a/b/c", 2))
}

type obj struct {
	S string
}

func (o obj) String() string {
	return o.S
}

func TestPathValues(t *testing.T) {
	require.Equal(t, "/o/abc", dstore.Path("o", &obj{S: "abc"}))
}
