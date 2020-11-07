package dstore

import (
	"fmt"
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
		case []string:
			strs = append(strs, v...)
		case int:
			strs = append(strs, strconv.Itoa(v))
		case int64:
			strs = append(strs, fmt.Sprintf("%d", v))
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

// PathFirst returns first path component.
func PathFirst(path string) string {
	return newPath(path).First()
}

// PathLast returns last path component.
func PathLast(path string) string {
	return newPath(path).Last()
}

// PathFrom skips first n components.
func PathFrom(path string, n int) string {
	pc := newPath(path).Components()
	if len(pc) > n {
		return Path(pc[n:])
	}
	return path
}
