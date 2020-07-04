package docs_test

import (
	"testing"

	"github.com/keys-pub/keys/docs"
	"github.com/stretchr/testify/require"
)

func TestPath(t *testing.T) {
	require.Equal(t, "/a/b", docs.Path("a", "b"))
	require.Equal(t, "/a/b/1", docs.Path("a", "b", 1))
	require.Equal(t, "/a", docs.Path("", "a"))
	require.Equal(t, "/a", docs.Path("a", ""))

	require.Equal(t, "/", docs.Path(""))
	require.Equal(t, "/", docs.Path("/"))
	require.Equal(t, "/a", docs.Path("a"))
	require.Equal(t, "/a", docs.Path("/a"))
	require.Equal(t, "/a", docs.Path("/a/"))
	require.Equal(t, "/a/b", docs.Path("/a//b/"))
}

func TestPathComponents(t *testing.T) {
	require.Equal(t, []string{"test", "sub"}, docs.PathComponents("/test//sub/"))
	require.Equal(t, []string{}, docs.PathComponents("/"))

	require.Equal(t, "", docs.PathLast(""))
	require.Equal(t, "", docs.PathLast("/"))
	require.Equal(t, "a", docs.PathLast("/a"))
	require.Equal(t, "b", docs.PathLast("/a/b"))

	require.Equal(t, "", docs.PathFirst(""))
	require.Equal(t, "", docs.PathFirst("/"))
	require.Equal(t, "a", docs.PathFirst("/a"))
	require.Equal(t, "a", docs.PathFirst("/a/b"))

	require.Equal(t, "/a", docs.PathFrom("/a", 1))
	require.Equal(t, "/b", docs.PathFrom("/a/b", 1))
	require.Equal(t, "/b/c", docs.PathFrom("/a/b/c", 1))
	require.Equal(t, "/c", docs.PathFrom("/a/b/c", 2))
}

type obj struct {
	S string
}

func (o obj) String() string {
	return o.S
}

func TestPathValues(t *testing.T) {
	require.Equal(t, "/o/abc", docs.Path("o", &obj{S: "abc"}))
}
