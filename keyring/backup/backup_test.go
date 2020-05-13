package backup_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/keyring/backup"
	"github.com/keys-pub/keys/util"
	"github.com/stretchr/testify/require"
)

type clock struct {
	t time.Time
}

func newClock() *clock {
	t := util.TimeFromMillis(1234567890000)
	return &clock{
		t: t,
	}
}

func (c *clock) Now() time.Time {
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

func TestBackup(t *testing.T) {
	clock := newClock()

	kr := keyring.NewMem(true)
	for i := 0; i < 10; i++ {
		err := kr.Create(keyring.NewItem(fmt.Sprintf("item%d", i), []byte("value"), "type", clock.Now()))
		require.NoError(t, err)
	}

	key := keys.Rand32()
	tmpFile := keys.RandTempPath("")
	store := backup.NewTGZStore(tmpFile, clock.Now)
	defer func() { _ = os.Remove(tmpFile) }()

	err := backup.Export(kr, store, key)
	require.NoError(t, err)

	kr2 := keyring.NewMem(true)
	err = backup.Import(kr2, store, keys.Rand32())
	require.EqualError(t, err, "invalid keyring auth")

	err = backup.Import(kr2, store, key)
	require.NoError(t, err)
	testEqualKeyrings(t, kr, kr2)

	// Import again
	err = backup.Import(kr2, store, key)
	require.NoError(t, err)
	testEqualKeyrings(t, kr, kr2)

	// Change local and import again, should error
	err = kr2.Update("item1", []byte("newvalue"))
	require.NoError(t, err)
	err = backup.Import(kr2, store, key)
	require.EqualError(t, err, "item already exists with different data")
}

func testEqualKeyrings(t *testing.T, kr1 *keyring.Keyring, kr2 *keyring.Keyring) {
	items1, err := kr1.List(nil)
	require.NoError(t, err)
	items2, err := kr2.List(nil)
	require.NoError(t, err)

	require.Equal(t, len(items1), len(items2))

	for i := 0; i < len(items1); i++ {
		item1, item2 := items1[i], items2[i]
		require.Equal(t, item1, item2)
	}
}
