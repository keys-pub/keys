package env_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keys-pub/keys"

	"github.com/keys-pub/keys/env"
	"github.com/stretchr/testify/require"
)

func TestMkdir(t *testing.T) {
	dir := "KeysTest-" + keys.RandFileName()
	defer os.RemoveAll(dir)

	path, err := env.AppPath(env.Dir(dir), env.File("test.txt"))
	require.NoError(t, err)

	exists, err := env.PathExists(dir)
	require.NoError(t, err)
	require.False(t, exists)

	exists, err = env.PathExists(path)
	require.NoError(t, err)
	require.False(t, exists)

	path, err = env.AppPath(env.Dir(dir), env.File("test.txt"), env.Mkdir())
	require.NoError(t, err)

	dir, file := filepath.Split(path)
	require.Equal(t, "test.txt", file)
	exists, err = env.PathExists(dir)
	require.NoError(t, err)
	require.True(t, exists)

	exists, err = env.PathExists(path)
	require.NoError(t, err)
	require.False(t, exists)
}
