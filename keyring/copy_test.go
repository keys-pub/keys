package keyring_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestCopy(t *testing.T) {
	var err error

	// Keyring #1 (mem)
	kr := keyring.NewMem(false)
	key := keys.Rand32()
	id := encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Base62)
	provision := &keyring.Provision{
		ID: id,
	}
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	item := keyring.NewItem(encoding.MustEncode(keys.RandBytes(32), encoding.Base62), []byte("testpassword"), "", time.Now())
	err = kr.Create(item)
	require.NoError(t, err)

	// Keyring #2 (mem)
	kr2 := keyring.NewMem(false)

	// Copy
	expected := []string{"#auth-0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29", "#provision-0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29", item.ID}
	ids, err := keyring.Copy(kr.Store(), kr2.Store())
	require.NoError(t, err)
	require.Equal(t, expected, ids)

	// Unlock #2
	_, err = kr2.Unlock(key)
	require.NoError(t, err)

	out, err := kr2.Get(item.ID)
	require.NoError(t, err)
	require.Equal(t, "testpassword", string(out.Data))

	// Copy (again)
	_, err = keyring.Copy(kr.Store(), kr2.Store())
	require.EqualError(t, err, "failed to copy: entry already exists #auth-0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29")

	// Copy (skip existing)
	ids, err = keyring.Copy(kr.Store(), kr2.Store(), keyring.SkipExisting())
	require.NoError(t, err)
	require.Equal(t, []string{}, ids)

	// Copy (dry-run)
	kr3 := keyring.NewMem(false)
	ids, err = keyring.Copy(kr.Store(), kr3.Store(), keyring.DryRun())
	require.NoError(t, err)
	require.Equal(t, expected, ids)

	out3, err := kr3.IDs(keyring.Hidden(), keyring.Reserved())
	require.NoError(t, err)
	require.Equal(t, 0, len(out3))
}
