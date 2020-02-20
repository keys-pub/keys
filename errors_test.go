package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

type errTest struct{}

func (t errTest) Error() string {
	return "temporary error"
}

func (t errTest) Temporary() bool {
	return true
}

func (t errTest) Timeout() bool {
	return true
}

func TestIsTemporaryError(t *testing.T) {
	require.True(t, keys.IsTemporaryError(&errTest{}))
}

func TestNewErrNotFound(t *testing.T) {
	require.EqualError(t, keys.NewErrNotFound("123"), "not found 123")
	require.EqualError(t, keys.NewErrNotFound(""), "not found")
}
