package keys

import (
	"bytes"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveLoadEdX25519Key(t *testing.T) {
	ks := NewMemKeystore()
	signKey := GenerateEdX25519Key()
	err := ks.SaveSignKey(signKey)
	require.NoError(t, err)
	signKeyOut, err := ks.SignKey(signKey.ID())
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
	require.Equal(t, signKey.PublicKey(), signKeyOut.PublicKey())
}

func TestEdX25519KeySeed(t *testing.T) {
	signKey := GenerateEdX25519Key()
	seed := signKey.Seed()
	signKeyOut := NewEdX25519KeyFromSeed(seed)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
}

func TestEdX25519KeySignVerify(t *testing.T) {
	signKey := GenerateEdX25519Key()

	b := []byte("test message")
	sig := Sign(b, signKey)

	bout, err := signKey.PublicKey().Verify(sig)
	require.NoError(t, err)
	require.Equal(t, b, bout)

	_, err = signKey.PublicKey().Verify(sig[0 : len(sig)-1])
	require.EqualError(t, err, "verify failed")

	sig2 := signKey.SignDetached(b)
	err = signKey.PublicKey().VerifyDetached(sig2, b)
	require.NoError(t, err)

	err = signKey.PublicKey().VerifyDetached(sig2, []byte{0x01})
	require.EqualError(t, err, "verify failed")
}

func TestNewEdX25519KeyFromPrivateKey(t *testing.T) {
	_ = NewEdX25519KeyFromPrivateKey(Bytes64(bytes.Repeat([]byte{0x01}, 64)))
}

func ExampleSign() {
	alice := GenerateEdX25519Key()
	msg := "I'm alice 🤓"
	sig := Sign([]byte(msg), alice)
	out, err := alice.PublicKey().Verify(sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(out))
	// Output:
	// I'm alice 🤓
}
