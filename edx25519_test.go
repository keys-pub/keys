package keys_test

import (
	"bytes"
	"fmt"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestSaveLoadEdX25519Key(t *testing.T) {
	ks := keys.NewMemKeyStore()
	signKey := keys.GenerateEdX25519Key()
	err := ks.SaveEdX25519Key(signKey)
	require.NoError(t, err)
	signKeyOut, err := ks.EdX25519Key(signKey.ID())
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
	require.Equal(t, signKey.PublicKey().Bytes(), signKeyOut.PublicKey().Bytes())
}

func TestEdX25519KeySeed(t *testing.T) {
	signKey := keys.GenerateEdX25519Key()
	seed := signKey.Seed()
	signKeyOut := keys.NewEdX25519KeyFromSeed(seed)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
}

func TestEdX25519KeySignVerify(t *testing.T) {
	signKey := keys.GenerateEdX25519Key()

	b := []byte("test message")
	sig := signKey.Sign(b)

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
	_ = keys.NewEdX25519KeyFromPrivateKey(keys.Bytes64(bytes.Repeat([]byte{0x01}, 64)))
}

func TestPublicKeyIDEquals(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	bid := sk.X25519Key().ID()

	require.True(t, keys.PublicKeyIDEquals(sk.ID(), sk.ID()))
	require.True(t, keys.PublicKeyIDEquals(sk.ID(), bid))
	require.True(t, keys.PublicKeyIDEquals(bid, bid))
	require.True(t, keys.PublicKeyIDEquals(bid, sk.ID()))
}

func ExampleGenerateEdX25519Key() {
	alice := keys.GenerateEdX25519Key()
	fmt.Printf("Alice: %s\n", alice.ID())
}

func ExampleEdX25519Key_Sign() {
	alice := keys.GenerateEdX25519Key()
	msg := "I'm alice 🤓"
	sig := alice.Sign([]byte(msg))
	out, err := alice.PublicKey().Verify(sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(out))
	// Output:
	// I'm alice 🤓
}
