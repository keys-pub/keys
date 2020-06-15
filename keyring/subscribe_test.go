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

func TestSubscribe(t *testing.T) {
	var err error

	kr, err := keyring.New(keyring.Mem())
	require.NoError(t, err)
	ch := kr.Subscribe("test")

	key := keys.Rand32()
	id := encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Base62)
	provision := &keyring.Provision{ID: id}
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	_, err = kr.Unlock(key)
	require.NoError(t, err)

	err = kr.Lock()
	require.NoError(t, err)

	event := <-ch
	require.IsType(t, event, keyring.UnlockEvent{})
	unlock := event.(keyring.UnlockEvent)
	require.Equal(t, provision.ID, unlock.Provision.ID)

	event = <-ch
	require.IsType(t, event, keyring.LockEvent{})

	_, err = kr.Unlock(key)
	require.NoError(t, err)

	item := keyring.NewItem("test", []byte("testdata"), "", time.Now())
	err = kr.Set(item)
	require.NoError(t, err)

	event = <-ch
	require.IsType(t, event, keyring.UnlockEvent{})
	event = <-ch
	require.IsType(t, event, keyring.SetEvent{})
	create := event.(keyring.SetEvent)
	require.Equal(t, item.ID, create.ID)

	kr.Unsubscribe("test")
}
