package keyring_test

import (
	"testing"

	"github.com/keys-pub/keys/keyring"
)

func testMem(t *testing.T) *keyring.Keyring {
	kr := keyring.NewMem(false)
	return kr
}

func TestMemKeyring(t *testing.T) {
	kr := testMem(t)
	defer func() { _ = kr.Reset() }()
	testKeyring(t, kr)
}

func TestMemReset(t *testing.T) {
	kr := testMem(t)
	defer func() { _ = kr.Reset() }()
	testReset(t, kr)
}

func TestMemUnlock(t *testing.T) {
	kr := testMem(t)
	defer func() { _ = kr.Reset() }()
	testUnlock(t, kr)
}

func TestMemReserved(t *testing.T) {
	kr := testMem(t)
	defer func() { _ = kr.Reset() }()
	testReserved(t, kr)
}

func TestMemAuth(t *testing.T) {
	kr := testMem(t)
	defer func() { _ = kr.Reset() }()
	testAuth(t, kr)
}

func TestMemIDs(t *testing.T) {
	kr := testMem(t)
	defer func() { _ = kr.Reset() }()
	testIDs(t, kr)
}

func TestMemStore(t *testing.T) {
	kr := testMem(t)
	testStore(t, kr.Store())
}
