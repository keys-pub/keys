package env_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keys-pub/keys/env"
	"github.com/stretchr/testify/require"
)

func TestPaths(t *testing.T) {
	appDir, err := env.AppPath(env.Dir("KeysEnvTest"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(env.MustHomeDir(), "/Library/Application Support/KeysEnvTest"), appDir)
	exists, err := env.PathExists(appDir)
	require.NoError(t, err)
	require.False(t, exists)

	logsDir, err := env.LogsPath(env.Dir("KeysEnvTest"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(env.MustHomeDir(), "/Library/Logs/KeysEnvTest"), logsDir)
	exists, err = env.PathExists(logsDir)
	require.NoError(t, err)
	require.False(t, exists)

	configPath, err := env.ConfigPath(env.Dir("KeysEnvTest"), env.File("test.txt"), env.Mkdir())
	require.NoError(t, err)
	require.Equal(t, configPath, filepath.Join(env.MustHomeDir(), "/Library/Application Support/KeysEnvTest/test.txt"))
	configDir, file := filepath.Split(configPath)
	require.Equal(t, configDir, filepath.Join(env.MustHomeDir(), "/Library/Application Support/KeysEnvTest")+"/")
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
		filepath.Join(env.MustHomeDir(), "/Library/Application Support/KeysEnvTest"),
		filepath.Join(env.MustHomeDir(), "/Library/Logs/KeysEnvTest"),
	}, dirs)
}
