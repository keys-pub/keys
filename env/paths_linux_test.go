package env_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keys-pub/keys/env"
	"github.com/stretchr/testify/require"
)

func TestDirs(t *testing.T) {
	appDir, err := env.AppPath(env.Dir("KeysTest"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(appDir, `/.local/share/KeysTest`))
	defer os.RemoveAll(appDir)

	logsDir, err := env.LogsPath(env.Dir("KeysTest"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(logsDir, `/.cache/KeysTest`))
	defer os.RemoveAll(logsDir)

	configPath, err := env.ConfigPath(env.Dir("KeysTest"), env.File("test.txt"), env.Mkdir())
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(configPath, "/.config/KeysTest/test.txt"))
	configDir, file := filepath.Split(configPath)
	require.True(t, strings.HasSuffix(configDir, "/.config/KeysTest/"))
	require.Equal(t, "test.txt", file)
	defer os.RemoveAll(configDir)
	exists, err = env.PathExists(configDir)
	require.NoError(t, err)
	require.True(t, exists)
}
