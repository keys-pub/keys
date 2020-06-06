package keyring_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func testFSV(t *testing.T) *keyring.Keyring {
	dir, err := ioutil.TempDir("", "KeysTest")
	require.NoError(t, err)
	kr, err := keyring.New(keyring.FS(dir, true))
	require.NoError(t, err)
	return kr
}

func TestFSVKeyring(t *testing.T) {
	kr := testFSV(t)
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

func TestFSVStore(t *testing.T) {
	path := keys.RandTempPath()
	defer os.RemoveAll(path)

	fs, err := keyring.NewFS(path, true)
	require.NoError(t, err)
	testStore(t, fs)
}

func TestFSVReset(t *testing.T) {
	kr := testFSV(t)
	defer func() { _ = kr.Reset() }()
	testReset(t, kr)
}

func TestFSVSetupUnlock(t *testing.T) {
	kr := testFSV(t)
	defer func() { _ = kr.Reset() }()
	testSetupUnlock(t, kr)
}

func TestFSVReserved(t *testing.T) {
	kr := testFSV(t)
	defer func() { _ = kr.Reset() }()
	testReserved(t, kr)
}

func TestFSVAuth(t *testing.T) {
	kr := testFSV(t)
	defer func() { _ = kr.Reset() }()
	testAuth(t, kr)
}

func TestFSVIDs(t *testing.T) {
	kr := testFSV(t)
	defer func() { _ = kr.Reset() }()
	testIDs(t, kr)
}
