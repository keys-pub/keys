package keyring_test

import (
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestExport(t *testing.T) {
	// Keyring #1 (mem)
	kr := keyring.NewMem(true)
	item := keyring.NewItem(keys.Rand3262(), []byte("testpassword"), "", time.Now())
	err := kr.Create(item)
	require.NoError(t, err)

	// Keyring #2 (mem)
	kr2 := keyring.NewMem(true)

	// Export
	changes, err := keyring.Export(kr, kr2)
	require.NoError(t, err)
	require.Equal(t, 1, len(changes.Add))
	require.Equal(t, item.ID, changes.Add[0].ID)
}
