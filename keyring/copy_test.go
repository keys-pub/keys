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

	item := keyring.NewItem(keys.Rand3262(), []byte("testpassword"), "", time.Now())
	err = kr.Create(item)
	require.NoError(t, err)

	// Keyring #2 (mem)
	kr2 := keyring.NewMem(false)

	// Copy
	ids, err := keyring.Copy(kr.Store(), kr2.Store())
	require.NoError(t, err)
	require.Equal(t, []string{"#auth-0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29", "#provision-0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29", item.ID}, ids)

	// Unlock #2
	_, err = kr2.Unlock(key)
	require.NoError(t, err)

	out, err := kr2.Get(item.ID)
	require.NoError(t, err)
	require.Equal(t, "testpassword", string(out.Data))
}
