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

	require.Equal(t, "", ds.LastPathComponent(""))
	require.Equal(t, "", ds.LastPathComponent("/"))
	require.Equal(t, "a", ds.LastPathComponent("/a"))
	require.Equal(t, "b", ds.LastPathComponent("/a/b"))
}

func TestPathComponents(t *testing.T) {
	require.Equal(t, []string{"test", "sub"}, ds.PathComponents("/test//sub/"))
	require.Equal(t, []string{}, ds.PathComponents("/"))
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
