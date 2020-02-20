package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
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
	require.Equal(t, "/a/b", keys.Path("a", "b"))
	require.Equal(t, "/a/b/1", keys.Path("a", "b", 1))
	require.Equal(t, "/a", keys.Path("", "a"))

	require.Equal(t, "/", keys.Path(""))
	require.Equal(t, "/", keys.Path("/"))
	require.Equal(t, "/a", keys.Path("a"))
	require.Equal(t, "/a", keys.Path("/a"))
	require.Equal(t, "/a", keys.Path("/a/"))
	require.Equal(t, "/a/b", keys.Path("/a//b/"))

	require.Equal(t, "", keys.LastPathComponent(""))
	require.Equal(t, "", keys.LastPathComponent("/"))
	require.Equal(t, "a", keys.LastPathComponent("/a"))
	require.Equal(t, "b", keys.LastPathComponent("/a/b"))
}

func TestPathComponents(t *testing.T) {
	require.Equal(t, []string{"test", "sub"}, keys.PathComponents("/test//sub/"))
	require.Equal(t, []string{}, keys.PathComponents("/"))
}

type obj struct {
	S string
}

func (o obj) String() string {
	return o.S
}

func TestPathValues(t *testing.T) {
	require.Equal(t, "/o/abc", keys.Path("o", &obj{S: "abc"}))
}
