package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestConvert(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	bpk, err := keys.Convert(alice.ID(), keys.X25519Public)
	require.NoError(t, err)
	require.Equal(t, keys.ID("kbx1rvd43h2sag2tvrdp0duse5p82nvhpjd6hpjwhv7q7vqklega8atshec5ws"), bpk.ID())

	bpk, err = keys.Convert(alice.PublicKey(), keys.X25519Public)
	require.NoError(t, err)
	require.Equal(t, keys.ID("kbx1rvd43h2sag2tvrdp0duse5p82nvhpjd6hpjwhv7q7vqklega8atshec5ws"), bpk.ID())
}
