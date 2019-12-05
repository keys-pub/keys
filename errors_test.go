package keys

import (
	"fmt"
	"testing"

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
	require.True(t, IsTemporaryError(&errTest{}))
}

func TestNewErrNotFound(t *testing.T) {
	kid := RandID()
	require.EqualError(t, NewErrNotFound(kid, PublicKeyType), fmt.Sprintf("public key not found %s", kid))
	require.EqualError(t, NewErrNotFound("", PassphraseType), "passphrase not found")
	require.EqualError(t, NewErrNotFound("", ""), "unknown item not found")
	require.EqualError(t, NewErrNotFound("123", ""), "unknown item not found 123")
}
