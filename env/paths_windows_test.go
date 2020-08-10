package env_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keys-pub/keys/env"
	"github.com/stretchr/testify/require"
)

func TestPaths(t *testing.T) {
	appDir, err := env.AppPath(env.Dir("KeysEnvTest"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(appDir, `\AppData\Local\KeysEnvTest`))
	exists, err := env.PathExists(appDir)
	require.NoError(t, err)
	require.False(t, exists)

	logsDir, err := env.LogsPath(env.Dir("KeysEnvTest"))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(logsDir, `\AppData\Local\KeysEnvTest`))
	exists, err = env.PathExists(logsDir)
	require.NoError(t, err)
	require.False(t, exists)

	configPath, err := env.ConfigPath(env.Dir("KeysEnvTest"), env.File("test.txt"), env.Mkdir())
	require.NoError(t, err)
	require.Equal(t, filepath.Join(env.MustHomeDir(), `\AppData\Roaming\KeysEnvTest\test.txt`), configPath)
	configDir, file := filepath.Split(configPath)
	require.Equal(t, filepath.Join(env.MustHomeDir(), `\AppData\Roaming\KeysEnvTest`)+`\`, configDir)
	require.Equal(t, "test.txt", file)
	defer os.RemoveAll(configDir)
	exists, err = env.PathExists(configDir)
	require.NoError(t, err)
	require.True(t, exists)
}

func TestAllDirs(t *testing.T) {
	dirs, err := env.AllDirs("KeysEnvTest")
	require.NoError(t, err)
	require.Equal(t, []string{
		filepath.Join(env.MustHomeDir(), `\AppData\Local\KeysEnvTest`),
		filepath.Join(env.MustHomeDir(), `\AppData\Roaming\KeysEnvTest`),
	}, dirs)
}
