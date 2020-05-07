package backup_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	tmpDir := os.TempDir()
	opts := &backup.ExportOpts{Now: clock.Now}

	path, err := backup.ExportToDirectory(kr, tmpDir, "testpassword", opts)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path) }()
	require.True(t, strings.HasPrefix(filepath.Base(path), "20090213T233130-"))
	require.True(t, strings.HasSuffix(filepath.Base(path), ".kpb"))

	kr2 := keyring.NewMem(true)
	err = backup.ImportFromFile(kr2, path, "wrongpassword")
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")

	err = backup.ImportFromFile(kr2, path, "testpassword")
	require.NoError(t, err)
	testEqualKeyrings(t, kr, kr2)

	// Import again
	err = backup.ImportFromFile(kr2, path, "testpassword")
	require.NoError(t, err)
	testEqualKeyrings(t, kr, kr2)

	// Change local and import again, should error
	err = kr2.Update("item1", []byte("newvalue"))
	require.NoError(t, err)
	err = backup.ImportFromFile(kr2, path, "testpassword")
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
