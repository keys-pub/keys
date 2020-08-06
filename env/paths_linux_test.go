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
	require.Equal(t, filepath.Join(env.MustHomeDir(), `/.local/share/KeysEnvTest`), appDir)
	exists, err := env.PathExists(appDir)
	require.NoError(t, err)
	require.False(t, exists)

	logsDir, err := env.LogsPath(env.Dir("KeysEnvTest"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(env.MustHomeDir(), `/.cache/KeysEnvTest`), logsDir)
	exists, err = env.PathExists(logsDir)
	require.NoError(t, err)
	require.False(t, exists)

	configPath, err := env.ConfigPath(env.Dir("KeysEnvTest"), env.File("test.txt"), env.Mkdir())
	require.NoError(t, err)
	require.Equal(t, filepath.Join(env.MustHomeDir(), "/.config/KeysEnvTest/test.txt"), configPath)
	configDir, file := filepath.Split(configPath)
	require.Equal(t, filepath.Join(env.MustHomeDir(), "/.config/KeysEnvTest/")+"/", configDir)
	require.Equal(t, "test.txt", file)
	defer os.RemoveAll(configDir)
	exists, err = env.PathExists(configDir)
	require.NoError(t, err)
	require.True(t, exists)
}

func TestAppPathXDG(t *testing.T) {
	prev := os.Getenv("XDG_DATA_HOME")
	defer func() { os.Setenv("XDG_DATA_HOME", prev) }()
	err := os.Setenv("XDG_DATA_HOME", "/test/data")
	require.NoError(t, err)

	configPath, err := env.AppPath(env.Dir("KeysEnvTest"))
	require.NoError(t, err)
	require.Equal(t, "/test/data/KeysEnvTest", configPath)
}

func TestConfigPathXDG(t *testing.T) {
	prev := os.Getenv("XDG_CONFIG_HOME")
	defer func() { os.Setenv("XDG_CONFIG_HOME", prev) }()
	err := os.Setenv("XDG_CONFIG_HOME", "/test/config")
	require.NoError(t, err)

	configPath, err := env.ConfigPath(env.Dir("KeysEnvTest"))
	require.NoError(t, err)
	require.Equal(t, "/test/config/KeysEnvTest", configPath)
}

func TestLogsPathXDG(t *testing.T) {
	prev := os.Getenv("XDG_CACHE_HOME")
	defer func() { os.Setenv("XDG_CACHE_HOME", prev) }()
	err := os.Setenv("XDG_CACHE_HOME", "/test/cache")
	require.NoError(t, err)

	configPath, err := env.LogsPath(env.Dir("KeysEnvTest"))
	require.NoError(t, err)
	require.Equal(t, "/test/cache/KeysEnvTest", configPath)
}

func TestAllDirs(t *testing.T) {
	dirs, err := env.All("KeysEnvTest")
	require.NoError(t, err)
	require.Equal(t, []string{
		filepath.Join(env.MustHomeDir(), "/.local/share/KeysEnvTest"),
		filepath.Join(env.MustHomeDir(), "/.config/KeysEnvTest"),
		filepath.Join(env.MustHomeDir(), "/.cache/KeysEnvTest"),
	}, dirs)
}
