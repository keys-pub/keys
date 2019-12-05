package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPath(t *testing.T) {
	p := newPath("/")
	require.Equal(t, "/", p.String())
	p = p.Append("a")
	require.Equal(t, "/a", p.String())
	p = p.Append("b/")
	require.Equal(t, "/a/b", p.String())
	p = p.Append("/")
	require.Equal(t, "/a/b", p.String())
	p = p.Append("")
	require.Equal(t, "/a/b", p.String())
}

func TestPath(t *testing.T) {
	require.Equal(t, "/a/b", Path("a", "b"))
	require.Equal(t, "/a/b/1", Path("a", "b", 1))
	require.Equal(t, "/a", Path("", "a"))

	require.Equal(t, "/", Path(""))
	require.Equal(t, "/", Path("/"))
	require.Equal(t, "/a", Path("a"))
	require.Equal(t, "/a", Path("/a"))
	require.Equal(t, "/a", Path("/a/"))
	require.Equal(t, "/a/b", Path("/a//b/"))

	require.Equal(t, "", LastPathComponent(""))
	require.Equal(t, "", LastPathComponent("/"))
	require.Equal(t, "a", LastPathComponent("/a"))
	require.Equal(t, "b", LastPathComponent("/a/b"))
}

func TestPathComponents(t *testing.T) {
	require.Equal(t, []string{"test", "sub"}, PathComponents("/test//sub/"))
	require.Equal(t, []string{}, PathComponents("/"))
}

type obj struct {
	S string
}

func (o obj) String() string {
	return o.S
}

func TestPathValues(t *testing.T) {
	require.Equal(t, "/o/abc", Path("o", &obj{S: "abc"}))
}
