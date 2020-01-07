package keys

import (
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveLoadSignKey(t *testing.T) {
	ks := NewMemKeystore()
	signKey := GenerateSignKey()
	err := ks.SaveSignKey(signKey)
	require.NoError(t, err)
	signKeyOut, err := ks.SignKey(signKey.ID())
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
	require.Equal(t, signKey.PublicKey(), signKeyOut.PublicKey())
}

func TestSignKeySeed(t *testing.T) {
	signKey := GenerateSignKey()
	seed := signKey.Seed()
	var b [SignKeySeedSize]byte
	copy(b[:], seed)
	signKeyOut, err := NewSignKeyFromSeed(&b)
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
}

func TestSignKeySignVerify(t *testing.T) {
	signKey := GenerateSignKey()

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

func TestSignKeyInvalid(t *testing.T) {
	signKey, err := NewSignKeyFromPrivateKey([]byte{0x01})
	require.EqualError(t, err, "invalid private key length 1")
	require.Nil(t, signKey)
}

func ExampleSign() {
	alice := GenerateSignKey()
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
