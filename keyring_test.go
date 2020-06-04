package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestX25519KeyItem(t *testing.T) {
	key := keys.GenerateX25519Key()
	out, err := keys.KeyForItem(keys.ItemForKey(key))
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}

func TestX25519PublicKeyItem(t *testing.T) {
	key := keys.GenerateX25519Key()
	out, err := keys.KeyForItem(keys.ItemForKey(key.ID()))
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}

func TestEdX25519KeyItem(t *testing.T) {
	key := keys.GenerateEdX25519Key()
	out, err := keys.KeyForItem(keys.ItemForKey(key))
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}

func TestEdX25519PublicKeyItem(t *testing.T) {
	key := keys.GenerateEdX25519Key()
	out, err := keys.KeyForItem(keys.ItemForKey(key.ID()))
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}
