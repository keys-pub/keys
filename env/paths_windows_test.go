package env_test

import (
	"os"
	"strings"
	"testing"

	"github.com/keys-pub/keys/env"
	"github.com/stretchr/testify/require"
)

func TestDirs(t *testing.T) {
	appDir, err := env.AppPath(env.Dir("KeysTest"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(appDir, `\AppData\Local\KeysTest`))
	logsDir, err := env.LogsPath(env.Dir("KeysTest"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(logsDir, `\AppData\Local\KeysTest`))

	err := os.Setenv("LOCALAPPDATA", "")
	require.NoError(t, err)
	_, err := env.AppPath(env.Dir("KeysTest"))
	require.EqualError(t, err, "LOCALAPPDATA not set")
}
