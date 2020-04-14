package util_test

import (
	"testing"

	"github.com/keys-pub/keys/util"
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
	require.True(t, util.IsTemporaryError(&errTest{}))
}
