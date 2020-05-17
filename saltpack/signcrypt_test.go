package saltpack_test

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
	"github.com/stretchr/testify/require"
)

func TestSigncrypt(t *testing.T) {
	alice := keys.GenerateEdX25519Key()
	bob := keys.GenerateEdX25519Key()

	message := []byte("hi bob")

	encrypted, err := saltpack.Signcrypt(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err := saltpack.SigncryptOpen(encrypted, saltpack.NewKeyStore(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	encrypted2, err := saltpack.SigncryptArmored(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err = saltpack.SigncryptArmoredOpen(encrypted2, saltpack.NewKeyStore(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	_, err = saltpack.Signcrypt(message, alice, keys.ID(""))
	require.EqualError(t, err, "invalid recipient: empty id")

	_, err = saltpack.Signcrypt(message, nil, bob.ID())
	require.EqualError(t, err, "no sender specified")

	// Duplicate recipient
	_, err = saltpack.Signcrypt(message, alice, bob.ID(), bob.ID())
	require.NoError(t, err)
}

func TestSigncryptStream(t *testing.T) {
	alice := keys.GenerateEdX25519Key()
	bob := keys.GenerateEdX25519Key()

	message := []byte("hi bob")

	var buf bytes.Buffer
	encrypted, err := saltpack.NewSigncryptStream(&buf, alice, bob.ID())
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	stream, sender, err := saltpack.NewSigncryptOpenStream(&buf, saltpack.NewKeyStore(bob))
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	var buf2 bytes.Buffer
	encrypted2, err := saltpack.NewSigncryptArmoredStream(&buf2, alice, bob.ID())
	require.NoError(t, err)
	n, err = encrypted2.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted2.Close()

	stream, sender, err = saltpack.NewSigncryptArmoredOpenStream(&buf2, saltpack.NewKeyStore(bob))
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err = ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestSigncryptOpenError(t *testing.T) {
	alice := keys.GenerateEdX25519Key()
	bob := keys.GenerateEdX25519Key()

	encrypted, err := saltpack.Signcrypt([]byte("alice's message"), alice, bob.ID())
	require.NoError(t, err)

	_, _, err = saltpack.SigncryptOpen(encrypted, saltpack.NewKeyStore())
	require.EqualError(t, err, "no decryption key found for message")
}
