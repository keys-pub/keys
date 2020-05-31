package backup_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/keyring/backup"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestBackup(t *testing.T) {
	var err error
	clock := tsutil.NewClock()

	kr := keyring.NewMem(true)
	for i := 0; i < 10; i++ {
		err := kr.Create(keyring.NewItem(fmt.Sprintf("item%d", i), []byte(fmt.Sprintf("value%d", i)), fmt.Sprintf("type%d", i), clock.Now()))
		require.NoError(t, err)
	}

	tmpFile := keys.RandTempPath("")
	tgz := backup.NewTGZ(tmpFile, clock.Now)
	defer func() { _ = os.Remove(tmpFile) }()

	err = tgz.Backup(kr.Service(), kr.Store())
	require.NoError(t, err)

	kr2 := keyring.NewMem(false)
	err = tgz.Restore(kr2.Service(), kr2.Store())
	require.NoError(t, err)
	testEqualKeyrings(t, kr.Service(), kr.Store(), kr2.Store())
}

func testEqualKeyrings(t *testing.T, service string, st1 keyring.Store, st2 keyring.Store) {
	ids1, err := st1.IDs(service, keyring.Reserved(), keyring.Hidden())
	require.NoError(t, err)
	ids2, err := st2.IDs(service, keyring.Reserved(), keyring.Hidden())
	require.NoError(t, err)

	require.Equal(t, len(ids1), len(ids2))

	for _, id := range ids1 {
		b1, err := st1.Get(service, id)
		require.NoError(t, err)
		b2, err := st2.Get(service, id)
		require.NoError(t, err)
		require.Equal(t, b1, b2)
	}
}
