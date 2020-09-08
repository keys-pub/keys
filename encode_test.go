package keys_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestEncodeKeyToSaltpack(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	msg, err := keys.EncodeSaltpackKey(sk, "testpassword")
	require.NoError(t, err)

	_, err = keys.DecodeSaltpackKey(msg, "invalidpassword", false)
	require.EqualError(t, err, "failed to decrypt saltpack encoded key: failed to decrypt with a password: secretbox open failed")

	skOut, err := keys.DecodeSaltpackKey(msg, "testpassword", false)
	require.NoError(t, err)

	require.Equal(t, sk.Type(), skOut.Type())
	require.Equal(t, sk.Bytes(), skOut.Bytes())
}

func ExampleDecodeSaltpackKey() {
	key := `BEGIN X25519 KEY MESSAGE.
	umCRo9iHIudLWoz 4Ugt0hUXQVJ7lhV p7A9mb3kOTg6PeV fhqetAc9ZOUjagi
	91gENEkp0xfjF2E Tyakwe90kzo1FNT gRacWRL5B59strN OoZYHQooqvlMKM.
	END X25519 KEY MESSAGE.`
	bob, err := keys.DecodeSaltpackKey(key, "", true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("bob: %s\n", bob.ID())
	// Output: bob: kbx18x22l7nemmxcj76f9l3aaflc5487lp5u5q778gpe3t3wzhlqvu8qxa9z07
}

func TestEncodeKeyDecodeKey(t *testing.T) {
	sk := keys.GenerateEdX25519Key()

	// Saltpack (password)
	msg, err := keys.EncodeKey(sk, keys.SaltpackEncoding, "testpassword")
	require.NoError(t, err)
	out, err := keys.DecodeKey(msg, keys.SaltpackEncoding, "testpassword")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())

	// Saltpack (no password)
	msg, err = keys.EncodeKey(sk, keys.SaltpackEncoding, "")
	require.NoError(t, err)
	out, err = keys.DecodeKey(msg, keys.SaltpackEncoding, "")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())

	// Saltpack (public)
	_, err = keys.EncodeKey(sk.PublicKey(), keys.SaltpackEncoding, "")
	require.EqualError(t, err, "failed to encode to saltpack: unsupported key ed25519-public")

	// SSH (public)
	msg, err = keys.EncodeKey(sk.PublicKey(), keys.SSHEncoding, "")
	require.NoError(t, err)
	out, err = keys.DecodeKey(msg, keys.SSHEncoding, "")
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Type(), out.Type())
	require.Equal(t, sk.PublicKey().Bytes(), out.Bytes())

	// SSH (password)
	msg, err = keys.EncodeKey(sk, keys.SSHEncoding, "testpassword")
	require.NoError(t, err)
	out, err = keys.DecodeKey(msg, keys.SSHEncoding, "testpassword")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())

	// SSH (no password)
	msg, err = keys.EncodeKey(sk, keys.SSHEncoding, "")
	require.NoError(t, err)
	out, err = keys.DecodeKey(msg, keys.SSHEncoding, "")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())
}
