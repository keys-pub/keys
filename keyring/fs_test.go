package keyring

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func testFS(t *testing.T) Keyring {
	dir, err := ioutil.TempDir("", "KeysTest.keyring")
	require.NoError(t, err)
	kr, err := NewFS(dir)
	require.NoError(t, err)
	return kr
}

func TestFSKeyring(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()
	testKeyring(t, kr)
}

func TestFSReset(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()
	testReset(t, kr)
}

func TestFSUnlock(t *testing.T) {
	kr := testFS(t)
	defer func() { _ = kr.Reset() }()
	testUnlock(t, kr)
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
