package keys_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/stretchr/testify/require"
)

func TestEdX25519KeySeed(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	seed := sk.Seed()
	skOut := keys.NewEdX25519KeyFromSeed(seed)
	require.Equal(t, sk.PrivateKey(), skOut.PrivateKey())
	require.True(t, sk.Equal(skOut))

	sk2 := keys.NewEdX25519KeyFromSeed(keys.Rand32())
	require.False(t, sk.Equal(sk2))
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

func TestSign(t *testing.T) {
	// private := encoding.MustHex("b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd")
	// public := encoding.MustHex("77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb")
	kp := encoding.DecodeHex("b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd" +
		"77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb")
	msg := encoding.DecodeHex("916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171" +
		"ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01" +
		"dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313" +
		"c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" +
		"376d7f3ac22ff372c18f613f2ae2e856af40")
	sig := encoding.DecodeHex("6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b" +
		"4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509")

	key := keys.NewEdX25519KeyFromPrivateKey(keys.Bytes64(kp))

	out := key.Sign(msg)
	require.Equal(t, sig, out[:64])

	out = key.SignDetached(msg)
	require.Equal(t, sig, out)
}

func TestEdX25519JSON(t *testing.T) {
	key := keys.GenerateEdX25519Key()

	type test struct {
		Key *keys.EdX25519Key `json:"key"`
	}

	b, err := json.Marshal(test{Key: key})
	require.NoError(t, err)

	var out test
	err = json.Unmarshal(b, &out)
	require.NoError(t, err)

	require.Equal(t, key.Bytes(), out.Key.Bytes())
}
