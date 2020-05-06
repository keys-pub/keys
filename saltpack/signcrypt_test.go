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
	// Alice
	ksa := keys.NewMemStore(true)
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.GenerateEdX25519Key()
	err := ksa.SaveEdX25519Key(alice)
	require.NoError(t, err)

	// Bob
	ksb := keys.NewMemStore(true)
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.GenerateEdX25519Key()
	err = ksb.SaveEdX25519Key(bob)
	require.NoError(t, err)

	message := []byte("hi bob")

	encrypted, err := spa.Signcrypt(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err := spb.SigncryptOpen(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	encrypted2, err := spa.SigncryptArmored(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err = spb.SigncryptArmoredOpen(encrypted2)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	_, err = spa.Signcrypt(message, alice, keys.ID(""))
	require.EqualError(t, err, "invalid recipient: empty id")

	_, err = spa.Signcrypt(message, nil, bob.ID())
	require.EqualError(t, err, "no sender specified")

	// Duplicate recipient
	_, err = spa.Signcrypt(message, alice, bob.ID(), bob.ID())
	require.NoError(t, err)
}

func TestSigncryptStream(t *testing.T) {
	// Alice
	ksa := keys.NewMemStore(true)
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.GenerateEdX25519Key()
	err := ksa.SaveEdX25519Key(alice)
	require.NoError(t, err)

	// Bob
	ksb := keys.NewMemStore(true)
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.GenerateEdX25519Key()
	err = ksb.SaveEdX25519Key(bob)
	require.NoError(t, err)
	message := []byte("hi bob")

	var buf bytes.Buffer
	encrypted, err := spa.NewSigncryptStream(&buf, alice, bob.ID())
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	stream, sender, err := spb.NewSigncryptOpenStream(&buf)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	var buf2 bytes.Buffer
	encrypted2, err := spa.NewSigncryptArmoredStream(&buf2, alice, bob.ID())
	require.NoError(t, err)
	n, err = encrypted2.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted2.Close()

	stream, sender, err = spb.NewSigncryptArmoredOpenStream(&buf2)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err = ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestSigncryptOpenError(t *testing.T) {
	ksa := keys.NewMemStore(true)
	alice := keys.GenerateEdX25519Key()
	err := ksa.SaveEdX25519Key(alice)
	require.NoError(t, err)
	bob := keys.GenerateEdX25519Key()
	err = ksa.SaveEdX25519Key(bob)
	require.NoError(t, err)
	spa := saltpack.NewSaltpack(ksa)

	encrypted, err := spa.Signcrypt([]byte("alice's message"), alice, bob.ID())
	require.NoError(t, err)

	ksb := keys.NewMemStore(true)
	spb := saltpack.NewSaltpack(ksb)

	_, _, err = spb.SigncryptOpen(encrypted)
	require.EqualError(t, err, "no decryption key found for message")
}
