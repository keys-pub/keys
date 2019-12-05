package keys

import (
	"strconv"
	"strings"
)

type path struct {
	components []string
}

type stringify interface {
	String() string
}

// newPath creates a path from a string.
// This path package doesn't recognize "." or ".." or relative paths, and is
// meant to be a simpler version of path or filepath.
func newPath(paths ...interface{}) path {
	return path{components: expand(toStrings(paths...))}
}

func newPathFromStrings(paths ...string) path {
	return path{components: expand(paths)}
}

func toStrings(is ...interface{}) []string {
	strs := make([]string, 0, len(is))
	for _, i := range is {
		switch v := i.(type) {
		case string:
			strs = append(strs, v)
		case int:
			strs = append(strs, strconv.Itoa(v))
		case stringify:
			strs = append(strs, v.String())
		default:
			panic("path argument not a string")
		}
	}
	return strs
}

func expand(paths []string) []string {
	// Split any strings with '/' and remove empty components
	ps := []string{}
	for _, p := range paths {
		spl := strings.Split(p, "/")
		for _, s := range spl {
			if s != "" {
				ps = append(ps, s)
			}
		}
	}
	return ps
}

// Append to path returns new path with paths appended.
func (p path) Append(paths ...interface{}) path {
	strs := toStrings(paths...)
	return newPathFromStrings(append(p.components, expand(strs)...)...)
}

func (p path) String() string {
	return "/" + strings.Join(p.components, "/")
}

func (p path) Components() []string {
	return p.components
}

func (p path) First() string {
	if len(p.components) == 0 {
		return ""
	}
	return p.components[0]
}

func (p path) Last() string {
	if len(p.components) == 0 {
		return ""
	}
	return p.components[len(p.components)-1]
}

// Path returns a path string from the specified paths or path components.
// The components can be strings, values with a String() function.
//
// For example,
//    Path("a", "b") => "/a/b"
//    Path("") => "/"
//    Path("/a/") => "/a"
//    Path("/a//b") => "/a/b"
func Path(paths ...interface{}) string {
	return newPath(paths...).String()
}

// PathComponents returns the components of a path.
func PathComponents(path string) []string {
	return newPath(path).Components()
}

// FirstPathComponent returns first path component.
func FirstPathComponent(path string) string {
	return newPath(path).First()
}

// LastPathComponent returns last path component.
func LastPathComponent(path string) string {
	return newPath(path).Last()
}

// PathType denotes the type of path.
type PathType string

// KeyPathType is a path with 2 components, meant for a syncable key/value
// store, like Firebase or leveldb.
const KeyPathType PathType = "key"

// URLPathType is a path with more than 2 components for web APIs.
const URLPathType PathType = "url"
