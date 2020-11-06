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

	out, sender, err := saltpack.SigncryptOpen(encrypted, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	encrypted2, err := saltpack.SigncryptArmored(message, "TEST", alice, bob.ID())
	require.NoError(t, err)

	out, sender, brand, err := saltpack.SigncryptOpenArmored(encrypted2, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, "TEST", brand)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	_, err = saltpack.Signcrypt(message, alice, keys.ID(""))
	require.EqualError(t, err, "invalid recipient: empty id")

	// Duplicate recipient
	_, err = saltpack.Signcrypt(message, alice, bob.ID(), bob.ID())
	require.NoError(t, err)
}

func TestSigncryptAnonymous(t *testing.T) {
	bob := keys.GenerateEdX25519Key()

	message := []byte("hi bob")

	encrypted, err := saltpack.Signcrypt(message, nil, bob.ID())
	require.NoError(t, err)

	out, sender, err := saltpack.SigncryptOpen(encrypted, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Nil(t, sender)
}

func TestSigncryptStream(t *testing.T) {
	alice := keys.GenerateEdX25519Key()
	bob := keys.GenerateEdX25519Key()
	message := []byte("hi bob")

	var buf bytes.Buffer
	stream, err := saltpack.NewSigncryptStream(&buf, alice, bob.ID())
	require.NoError(t, err)
	n, err := stream.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	stream.Close()
	encrypted := copyBytes(buf.Bytes())

	dstream, sender, err := saltpack.NewSigncryptOpenStream(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	dstream, key, enc, armored, err := saltpack.NewReader(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, saltpack.SigncryptEncoding, enc)
	require.False(t, armored)
	require.Equal(t, alice.PublicKey().ID(), key.ID())
	out, err = ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestSigncryptArmoredStream(t *testing.T) {
	alice := keys.GenerateEdX25519Key()
	bob := keys.GenerateEdX25519Key()
	message := []byte("hi bob")

	var buf bytes.Buffer
	stream, err := saltpack.NewSigncryptArmoredStream(&buf, "TEST", alice, bob.ID())
	require.NoError(t, err)
	n, err := stream.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	stream.Close()
	encrypted := copyBytes(buf.Bytes())

	dstream, sender, brand, err := saltpack.NewSigncryptOpenArmoredStream(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	require.Equal(t, "TEST", brand)
	out, err := ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	dstream, key, enc, armored, err := saltpack.NewReader(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, saltpack.SigncryptEncoding, enc)
	require.True(t, armored)
	require.Equal(t, alice.PublicKey().ID(), key.ID())
	out, err = ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestSigncryptOpenError(t *testing.T) {
	alice := keys.GenerateEdX25519Key()
	bob := keys.GenerateEdX25519Key()

	encrypted, err := saltpack.Signcrypt([]byte("alice's message"), alice, bob.ID())
	require.NoError(t, err)

	_, _, err = saltpack.SigncryptOpen(encrypted, saltpack.NewKeyring())
	require.EqualError(t, err, "no decryption key found for message")
}
