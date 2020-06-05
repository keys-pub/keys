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
	kr, err := keyring.New(keyring.FSV(dir))
	require.NoError(t, err)
	return kr
}

func TestFSVKeyring(t *testing.T) {
	kr := testFSV(t)
	defer func() { _ = kr.Reset() }()
	testKeyring(t, kr)
}

func TestFSVStore(t *testing.T) {
	path := keys.RandTempPath()
	defer os.RemoveAll(path)

	fs, err := keyring.NewFSV(path)
	require.NoError(t, err)
	testStore(t, fs)
}
