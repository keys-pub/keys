package keyring_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestBackupRestore(t *testing.T) {
	var err error
	clock := tsutil.NewTestClock()

	kr := keyring.NewMem()
	for i := 0; i < 10; i++ {
		err := kr.Set(docs.Path("item", i), []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
	}

	tmpFile := keys.RandTempPath() + ".tgz"
	defer func() { _ = os.Remove(tmpFile) }()

	err = keyring.Backup(tmpFile, kr, clock.Now())
	require.NoError(t, err)

	kr2 := keyring.NewMem()
	err = keyring.Restore(tmpFile, kr2)
	require.NoError(t, err)
	testEqualKeyrings(t, kr, kr2)
}

func testEqualKeyrings(t *testing.T, kr1 keyring.Keyring, kr2 keyring.Keyring) {
	docs1, err := kr1.Documents()
	require.NoError(t, err)
	docs2, err := kr2.Documents()
	require.NoError(t, err)

	require.Equal(t, len(docs1), len(docs2))

	for i := 0; i < len(docs1); i++ {
		b1, err := kr1.Get(docs1[i].Path)
		require.NoError(t, err)
		b2, err := kr2.Get(docs2[i].Path)
		require.NoError(t, err)
		require.Equal(t, b1, b2)
	}
}
