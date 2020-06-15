package keyring_test

import (
	"testing"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func testMem(t *testing.T, unlocked bool) *keyring.Keyring {
	kr, err := keyring.New(keyring.Mem())
	require.NoError(t, err)
	if unlocked {
		kr.SetMasterKey(rand32())
	}
	return kr
}

func TestMemKeyring(t *testing.T) {
	kr := testMem(t, false)
	defer func() { _ = kr.Reset() }()
	testKeyring(t, kr)
}

func TestMemReset(t *testing.T) {
	kr := testMem(t, false)
	defer func() { _ = kr.Reset() }()
	testReset(t, kr)
}

func TestMemSetupUnlock(t *testing.T) {
	kr := testMem(t, false)
	defer func() { _ = kr.Reset() }()
	testSetupUnlock(t, kr)
}

func TestMemAuth(t *testing.T) {
	kr := testMem(t, false)
	defer func() { _ = kr.Reset() }()
	testAuth(t, kr)
}

func TestMemIDs(t *testing.T) {
	kr := testMem(t, false)
	defer func() { _ = kr.Reset() }()
	testIDs(t, kr)
}

func TestMemStore(t *testing.T) {
	kr := testMem(t, false)
	testStore(t, kr.Store())
}
