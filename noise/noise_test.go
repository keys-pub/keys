package noise_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/noise"
	"github.com/stretchr/testify/require"
)

func TestNewNoise(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	na, err := noise.NewHandshake(alice, bob.PublicKey(), true)
	require.NoError(t, err)

	nb, err := noise.NewHandshake(bob, alice.PublicKey(), false)
	require.NoError(t, err)

	// -> s
	// <- s
	b, err := na.Write([]byte("abcdef"))
	require.NoError(t, err)
	hb1, err := nb.Read(b)
	require.NoError(t, err)
	require.Equal(t, "abcdef", string(hb1))

	require.False(t, na.Complete())
	require.False(t, nb.Complete())

	// -> e, es, ss
	// <- e, ee, se
	b, err = nb.Write(nil)
	require.NoError(t, err)
	hb2, err := na.Read(b)
	require.NoError(t, err)
	require.Equal(t, "", string(hb2))

	require.True(t, na.Complete())
	require.True(t, nb.Complete())

	// transport I -> R
	encrypted, err := na.Encrypt(nil, nil, []byte("hello"))
	require.NoError(t, err)
	decrypted, err := nb.Decrypt(nil, nil, encrypted)
	require.NoError(t, err)
	require.Equal(t, "hello", string(decrypted))

	// transport R -> I
	encrypted, err = nb.Encrypt(nil, nil, []byte("what time is the meeting?"))
	require.NoError(t, err)
	decrypted, err = na.Decrypt(nil, nil, encrypted)
	require.NoError(t, err)
	require.Equal(t, "what time is the meeting?", string(decrypted))
}
