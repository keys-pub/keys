package env_test

import (
	"strings"
	"testing"

	"github.com/keys-pub/keys/env"
	"github.com/stretchr/testify/require"
)

func TestDirs(t *testing.T) {
	appDir, err := env.AppPath(env.Dir("KeysTest"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(appDir, "/Library/Application Support/KeysTest"))
	logsDir, err := env.LogsPath(env.Dir("KeysTest"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(logsDir, "/Library/Logs/KeysTest"))
}
