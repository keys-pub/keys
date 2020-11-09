package keyring_test

import (
	"runtime"
	"testing"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func skipSystem(t *testing.T) bool {
	if runtime.GOOS == "linux" {
		if err := keyring.CheckSystem(); err != nil {
			t.Skip()
			return true
		}
	}
	return false
}

func TestKeyring(t *testing.T) {
	if skipSystem(t) {
		return
	}
	sys, err := keyring.NewSystem("KeysTest")
	require.NoError(t, err)
	defer func() { _ = sys.Reset() }()
	testKeyring(t, sys)
}

func testKeyring(t *testing.T, kr keyring.Keyring) {
	paths, err := keyring.IDs(kr, "")
	require.NoError(t, err)
	require.Equal(t, 0, len(paths))

	exists, err := kr.Exists("key1")
	require.NoError(t, err)
	require.False(t, exists)

	data, err := kr.Get("key1")
	require.NoError(t, err)
	require.Nil(t, data)

	err = kr.Set("key1", []byte("val1"))
	require.NoError(t, err)

	out, err := kr.Get("key1")
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, []byte("val1"), out)

	exists, err = kr.Exists("key1")
	require.NoError(t, err)
	require.True(t, exists)

	err = kr.Set("key1", []byte("val1.new"))
	require.NoError(t, err)

	out, err = kr.Get("key1")
	require.NoError(t, err)
	require.Equal(t, []byte("val1.new"), out)

	items, err := kr.Items("")
	require.NoError(t, err)
	require.Equal(t, 1, len(items))
	require.Equal(t, []byte("val1.new"), items[0].Data)

	paths, err = keyring.IDs(kr, "")
	require.NoError(t, err)
	require.Equal(t, 1, len(paths))
	require.Equal(t, paths[0], "key1")

	ok, err := kr.Delete("key1")
	require.NoError(t, err)
	require.True(t, ok)

	out, err = kr.Get("key1")
	require.NoError(t, err)
	require.Nil(t, out)

	exists, err = kr.Exists("key1")
	require.NoError(t, err)
	require.False(t, exists)

	ok, err = kr.Delete("key1")
	require.NoError(t, err)
	require.False(t, ok)

	items, err = kr.Items("")
	require.NoError(t, err)
	require.Equal(t, 0, len(items))

	// Test paths
	err = kr.Set("/collection/key1", []byte("val1"))
	require.NoError(t, err)

	out, err = kr.Get("/collection/key1")
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, []byte("val1"), out)
}

func TestReset(t *testing.T) {
	if skipSystem(t) {
		return
	}
	sys, err := keyring.NewSystem("KeysTest")
	require.NoError(t, err)
	defer func() { _ = sys.Reset() }()
	testReset(t, sys)
}

func testReset(t *testing.T, kr keyring.Keyring) {
	var err error
	err = kr.Set("key1", []byte("password"))
	require.NoError(t, err)

	err = kr.Reset()
	require.NoError(t, err)

	out, err := kr.Get("key1")
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestDocuments(t *testing.T) {
	if skipSystem(t) {
		return
	}
	sys, err := keyring.NewSystem("KeysTest")
	require.NoError(t, err)
	defer func() { _ = sys.Reset() }()
	testDocuments(t, sys)
}

func testDocuments(t *testing.T, kr keyring.Keyring) {
	var err error

	// TODO: Implement index/limit options

	err = kr.Set("akey1", []byte("aval1"))
	require.NoError(t, err)
	err = kr.Set("akey2", []byte("aval2"))
	require.NoError(t, err)
	err = kr.Set("bkey1", []byte("bval1"))
	require.NoError(t, err)

	out, err := kr.Items("")
	require.NoError(t, err)
	require.Equal(t, 3, len(out))
	require.Equal(t, "akey1", out[0].ID)
	require.Equal(t, []byte("aval1"), out[0].Data)

	out, err = kr.Items("b")
	require.NoError(t, err)
	require.Equal(t, 1, len(out))
	require.Equal(t, "bkey1", out[0].ID)
	require.Equal(t, []byte("bval1"), out[0].Data)
}
