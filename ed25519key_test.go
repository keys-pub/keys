package keys

import (
	"bytes"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveLoadEd25519Key(t *testing.T) {
	ks := NewMemKeystore()
	signKey := GenerateEd25519Key()
	err := ks.SaveSignKey(signKey)
	require.NoError(t, err)
	signKeyOut, err := ks.SignKey(signKey.ID())
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
	require.Equal(t, signKey.PublicKey(), signKeyOut.PublicKey())
}

func TestEd25519KeySeed(t *testing.T) {
	signKey := GenerateEd25519Key()
	seed := signKey.Seed()
	signKeyOut := NewEd25519KeyFromSeed(seed)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
}

func TestEd25519KeySignVerify(t *testing.T) {
	signKey := GenerateEd25519Key()

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

func TestNewEd25519KeyFromPrivateKey(t *testing.T) {
	_ = NewEd25519KeyFromPrivateKey(Bytes64(bytes.Repeat([]byte{0x01}, 64)))
}

func ExampleSign() {
	alice := GenerateEd25519Key()
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
