package keyring_test

import (
	"io/ioutil"
	"testing"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func testFS(t *testing.T) *keyring.Keyring {
	dir, err := ioutil.TempDir("", "KeysTest.keyring")
	require.NoError(t, err)
	kr, err := keyring.New(keyring.FS(dir, false))
	require.NoError(t, err)
	return kr
}

func TestFSKeyring(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()

	testKeyring(t, kr)

	_, err := kr.Get(".")
	require.EqualError(t, err, `failed to get keyring item: invalid id "."`)
	_, err = kr.Get("..")
	require.EqualError(t, err, `failed to get keyring item: invalid id ".."`)
	_, err = kr.Get("foo/bar")
	require.EqualError(t, err, `failed to get keyring item: invalid id "foo/bar"`)
	_, err = kr.Get(`\foo`)
	require.EqualError(t, err, `failed to get keyring item: invalid id "\\foo"`)
}

func TestFSReset(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()
	testReset(t, kr)
}

func TestFSSetupUnlock(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()
	testSetupUnlock(t, kr)
}

func TestFSReserved(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()
	testReserved(t, kr)
}

func TestFSAuth(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()
	testAuth(t, kr)
}

func TestFSIDs(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()
	testIDs(t, kr)
}
