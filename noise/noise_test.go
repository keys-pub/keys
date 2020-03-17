package noise_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/noise"
	"github.com/stretchr/testify/require"
)

func TestNewNoise(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	na, err := noise.NewNoise(alice, bob.PublicKey(), true)
	require.NoError(t, err)

	nb, err := noise.NewNoise(bob, alice.PublicKey(), false)
	require.NoError(t, err)

	// -> s
	// <- s
	b, err := na.HandshakeWrite([]byte("abcdef"))
	require.NoError(t, err)
	hb1, err := nb.HandshakeRead(b)
	require.NoError(t, err)
	require.Equal(t, "abcdef", string(hb1))

	require.False(t, na.HandshakeComplete())
	require.False(t, nb.HandshakeComplete())

	// -> e, es, ss
	// <- e, ee, se
	b, err = nb.HandshakeWrite(nil)
	require.NoError(t, err)
	hb2, err := na.HandshakeRead(b)
	require.NoError(t, err)
	require.Equal(t, "", string(hb2))

	require.True(t, na.HandshakeComplete())
	require.True(t, nb.HandshakeComplete())

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

func ExampleNewNoise() {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	na, err := noise.NewNoise(alice, bob.PublicKey(), true)
	if err != nil {
		log.Fatal(err)
	}

	nb, err := noise.NewNoise(bob, alice.PublicKey(), false)
	if err != nil {
		log.Fatal(err)
	}

	// -> s
	// <- s
	ha, err := na.HandshakeWrite(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := nb.HandshakeRead(ha); err != nil {
		log.Fatal(err)
	}
	// -> e, es, ss
	// <- e, ee, se
	hb, err := nb.HandshakeWrite(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := na.HandshakeRead(hb); err != nil {
		log.Fatal(err)
	}

	// transport I -> R
	encrypted, err := na.Encrypt(nil, nil, []byte("hello"))
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := nb.Decrypt(nil, nil, encrypted)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", string(decrypted))
	// Output: hello
}
