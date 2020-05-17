package saltpack_test

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	alice := keys.NewX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewX25519KeyFromSeed(testSeed(0x02))

	message := []byte("hi bob")

	encrypted, err := saltpack.Encrypt(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err := saltpack.Decrypt(encrypted, bob)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	encrypted2, err := saltpack.EncryptArmored(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err = saltpack.DecryptArmored(encrypted2, bob)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	// Decrypt without last character '.'
	// TODO: Patch keybase/saltpack to allow
	// trunc := encrypted2[:len(encrypted2)-2]
	// out, sender, err = spb.DecryptArmored(trunc)
	// require.NoError(t, err)
	// require.Equal(t, message, out)
	// require.NotNil(t, sender)
	// require.Equal(t, alice.PublicKey().ID(), sender.ID())

	_, err = saltpack.Encrypt(message, alice, keys.ID(""))
	require.EqualError(t, err, "invalid recipient: empty id")

	// Duplicate recipient
	_, err = saltpack.Encrypt(message, alice, bob.ID(), bob.ID())
	require.NoError(t, err)
}

func TestEncryptAnon(t *testing.T) {
	bob := keys.NewX25519KeyFromSeed(testSeed(0x02))
	message := []byte("hi bob")
	// Anon sender
	encrypted, err := saltpack.Encrypt(message, nil, bob.ID())
	require.NoError(t, err)
	out, sender, err := saltpack.Decrypt(encrypted, bob)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Nil(t, sender)
}

func TestEncryptStream(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()
	message := []byte("hi bob")

	var buf bytes.Buffer
	encrypted, err := saltpack.NewEncryptStream(&buf, alice, bob.ID())
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	stream, sender, err := saltpack.NewDecryptStream(&buf, bob)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	var buf2 bytes.Buffer
	encrypted2, err := saltpack.NewEncryptArmoredStream(&buf2, alice, bob.ID())
	require.NoError(t, err)
	n, err = encrypted2.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted2.Close()

	stream, sender, err = saltpack.NewDecryptArmoredStream(&buf2, bob)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err = ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptStreamAnon(t *testing.T) {
	bob := keys.GenerateX25519Key()
	message := []byte("hi bob, its anon")

	// Anon sender
	var buf bytes.Buffer
	encrypted, err := saltpack.NewEncryptStream(&buf, nil, bob.ID())
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	stream, sender, err := saltpack.NewDecryptStream(&buf, bob)
	require.NoError(t, err)
	require.Nil(t, sender)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptOpenError(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	encrypted, err := saltpack.Encrypt([]byte("alice's message"), alice, bob.ID())
	require.NoError(t, err)

	_, _, err = saltpack.Decrypt(encrypted)
	require.EqualError(t, err, "no decryption key found for message")
}

func TestEncryptWithEdX25519Key(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	message := []byte("hi bob")

	encrypted, err := saltpack.Encrypt(message, alice.X25519Key(), bob.ID())
	require.NoError(t, err)

	out, sender, err := saltpack.Decrypt(encrypted, bob)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.X25519Key().PublicKey().ID(), sender.ID())
}
