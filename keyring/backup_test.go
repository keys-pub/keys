package keyring_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestBackupRestore(t *testing.T) {
	var err error
	clock := tsutil.NewClock()

	kr := keyring.NewMem(false)

	err = kr.UnlockWithPassword("testpassword", true)
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		err := kr.Create(keyring.NewItem(fmt.Sprintf("item%d", i), []byte(fmt.Sprintf("value%d", i)), fmt.Sprintf("type%d", i), clock.Now()))
		require.NoError(t, err)
	}

	tmpFile := keys.RandTempPath() + ".tgz"
	defer func() { _ = os.Remove(tmpFile) }()

	err = keyring.Backup(tmpFile, kr.Store(), clock.Now())
	require.NoError(t, err)

	kr2 := keyring.NewMem(false)
	err = keyring.Restore(tmpFile, kr2.Store())
	require.NoError(t, err)
	testEqualKeyrings(t, kr.Store(), kr2.Store())

	err = kr2.UnlockWithPassword("testpassword", false)
	require.NoError(t, err)
}

func testEqualKeyrings(t *testing.T, st1 keyring.Store, st2 keyring.Store) {
	ids1, err := st1.IDs(keyring.Reserved(), keyring.Hidden())
	require.NoError(t, err)
	ids2, err := st2.IDs(keyring.Reserved(), keyring.Hidden())
	require.NoError(t, err)

	require.Equal(t, len(ids1), len(ids2))

	for _, id := range ids1 {
		b1, err := st1.Get(id)
		require.NoError(t, err)
		b2, err := st2.Get(id)
		require.NoError(t, err)
		require.Equal(t, b1, b2)
	}
}
