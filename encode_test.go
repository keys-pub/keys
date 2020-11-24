package keys_test

import (
	"encoding/hex"
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
	msg := `BEGIN EDX25519 KEY MESSAGE.
	AY6gPAVx9JSUsLg 3K8CNqUyNY87qiL FNNp7UBsIcvObJK mRtDzpcwQU1XpYa
	64FF0g4O0sDrhV4 qlp52vdQ5PG77D8 046ZdckukUl6reZ inOEqkDuOg5hynz
	k95BEExR31Sqenh rdqT3ADIdPu8f4f aXQaFejAp3Cb.
	END EDX25519 KEY MESSAGE.`
	key, err := keys.DecodeSaltpackKey(msg, "testpassword", true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", key.ID())
	// Output: kex10x6fdaazp2zy85m6cj7w57y4u0cc99xa3nmwjdldk9l4ajm3yadq70g0js
}

func TestEncodeKeyDecodeKey(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

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

	// SSH (password, helper)
	msg, err = keys.EncodeSSHKey(sk, "testpassword")
	require.NoError(t, err)
	out, err = keys.DecodeSSHKey(msg, "testpassword")
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

	// SSH (no password, helper)
	msg, err = keys.EncodeSSHKey(sk, "")
	require.NoError(t, err)
	out, err = keys.DecodeSSHKey(msg, "")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())

	// SSH
	pk, err := keys.DecodeSSHKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c", "")
	require.NoError(t, err)
	require.Equal(t, "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c", hex.EncodeToString(pk.Bytes()))

	// Errors
	_, err = keys.DecodeKey("", keys.SSHEncoding, "")
	require.EqualError(t, err, "failed to decode ssh key: empty string")
	_, err = keys.DecodeKey("", keys.SaltpackEncoding, "")
	require.EqualError(t, err, "failed to decode saltpack key: empty string")
}

func ExampleEncodeSSHKey() {
	sk := keys.GenerateEdX25519Key()

	privateKey, err := keys.EncodeSSHKey(sk, "testpassword")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s\n", privateKey)

	publicKey, err := keys.EncodeSSHKey(sk.PublicKey(), "")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s\n", publicKey)

	// Output:
	//
}

func ExampleDecodeSSHKey() {
	pk, err := keys.DecodeSSHKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29c", "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", pk.ID())
	// Output: kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077
}
