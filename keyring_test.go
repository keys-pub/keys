package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestX25519KeyItem(t *testing.T) {
	key := keys.GenerateX25519Key()
	item := keys.NewX25519KeyItem(key)

	out, err := keys.AsX25519Key(item)
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}

func TestEdX25519KeyItem(t *testing.T) {
	key := keys.GenerateEdX25519Key()
	item := keys.NewEdX25519KeyItem(key)

	out, err := keys.AsEdX25519Key(item)
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}
