package keyring_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func testFS(t *testing.T) (keyring.Store, func()) {
	dir, err := ioutil.TempDir("", "KeysTest.keyring")
	require.NoError(t, err)
	fs, err := keyring.NewFS(dir)
	require.NoError(t, err)
	closeFn := func() {
		os.RemoveAll(dir)
	}
	return fs, closeFn
}

func TestFSStore(t *testing.T) {
	st, closeFn := testFS(t)
	defer closeFn()
	testStore(t, st)

	_, err := st.Get(".")
	require.EqualError(t, err, "invalid path .")
	_, err = st.Get("..")
	require.EqualError(t, err, "invalid path ..")
}

func TestFSReset(t *testing.T) {
	st, closeFn := testFS(t)
	defer closeFn()
	testReset(t, st)
}

func TestFSDocuments(t *testing.T) {
	st, closeFn := testFS(t)
	defer closeFn()
	testDocuments(t, st)
}
