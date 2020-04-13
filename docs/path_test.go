package docs_test

import (
	"testing"

	"github.com/keys-pub/keys/docs"
	"github.com/stretchr/testify/require"
)

// func TestNewPath(t *testing.T) {
// 	p := keys.newPath("/")
// 	require.Equal(t, "/", p.String())
// 	p = p.Append("a")
// 	require.Equal(t, "/a", p.String())
// 	p = p.Append("b/")
// 	require.Equal(t, "/a/b", p.String())
// 	p = p.Append("/")
// 	require.Equal(t, "/a/b", p.String())
// 	p = p.Append("")
// 	require.Equal(t, "/a/b", p.String())
// }

func TestPath(t *testing.T) {
	require.Equal(t, "/a/b", docs.Path("a", "b"))
	require.Equal(t, "/a/b/1", docs.Path("a", "b", 1))
	require.Equal(t, "/a", docs.Path("", "a"))

	require.Equal(t, "/", docs.Path(""))
	require.Equal(t, "/", docs.Path("/"))
	require.Equal(t, "/a", docs.Path("a"))
	require.Equal(t, "/a", docs.Path("/a"))
	require.Equal(t, "/a", docs.Path("/a/"))
	require.Equal(t, "/a/b", docs.Path("/a//b/"))

	require.Equal(t, "", docs.LastPathComponent(""))
	require.Equal(t, "", docs.LastPathComponent("/"))
	require.Equal(t, "a", docs.LastPathComponent("/a"))
	require.Equal(t, "b", docs.LastPathComponent("/a/b"))
}

func TestPathComponents(t *testing.T) {
	require.Equal(t, []string{"test", "sub"}, docs.PathComponents("/test//sub/"))
	require.Equal(t, []string{}, docs.PathComponents("/"))
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
