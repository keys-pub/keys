package keyring_test

import (
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestCopy(t *testing.T) {
	var err error

	// Keyring #1 (mem)
	kr := keyring.NewMem(false)
	authID, err := kr.SetupWithPassword("testkeyringpassword")
	require.NoError(t, err)

	item := keyring.NewItem(keys.Rand3262(), []byte("testpassword"), "", time.Now())
	err = kr.Create(item)
	require.NoError(t, err)

	// Keyring #2 (mem)
	kr2 := keyring.NewMem(false)

	// Copy
	ids, err := keyring.Copy(kr, kr2)
	require.NoError(t, err)
	require.Equal(t, []string{authID, "#salt", item.ID}, ids)

	// Unlock #2
	err = kr2.UnlockWithPassword("testkeyringpassword")
	require.NoError(t, err)

	out, err := kr2.Get(item.ID)
	require.NoError(t, err)
	require.Equal(t, "testpassword", string(out.Data))
}
