package keys

import (
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

// func TestSaveLoadSignKey(t *testing.T) {
// 	ks := NewMemKeystore()

// 	signKey := GenerateSignKey()

// 	err := ks.SaveSignKey(signKey)
// 	require.NoError(t, err)

// 	signKeyOut, err := ks.SignKey(signKey.ID)
// 	require.NoError(t, err)

// 	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
// 	require.Equal(t, signKey.PublicKey, signKeyOut.PublicKey)
// }

func TestSignKeySeed(t *testing.T) {
	signKey := GenerateSignKey()
	seed := signKey.Seed()
	var sba [SeedSize]byte
	copy(sba[:], seed)
	signKeyOut, err := NewSignKeyFromSeed(&sba)
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())
}

func TestSignKeySignVerify(t *testing.T) {
	signKey := GenerateSignKey()

	b := []byte("test message")
	sig := Sign(b, signKey)

	bout, err := Verify(sig, signKey.PublicKey)
	require.NoError(t, err)
	require.Equal(t, b, bout)

	_, err = Verify(sig[0:len(sig)-1], signKey.PublicKey)
	require.EqualError(t, err, "verify failed")

	sig2 := signKey.SignDetached(b)
	err = VerifyDetached(sig2, b, signKey.PublicKey)
	require.NoError(t, err)

	err = VerifyDetached(sig2, []byte{0x01}, signKey.PublicKey)
	require.EqualError(t, err, "verify failed")
}

func TestSignKeyEmpty(t *testing.T) {
	signKey, err := NewSignKey([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	require.EqualError(t, err, "empty private key bytes")
	require.Nil(t, signKey)
}

func TestSignKeyInvalid(t *testing.T) {
	signKey, err := NewSignKey([]byte{0x01})
	require.EqualError(t, err, "invalid private key length 1")
	require.Nil(t, signKey)
}

func ExampleSign() {
	aliceSK := GenerateKey().SignKey()
	msg := "I'm alice 🤓"
	sig := Sign([]byte(msg), aliceSK)
	out, err := Verify(sig, aliceSK.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(out))
	// Output:
	// I'm alice 🤓
}
