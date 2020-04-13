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
	// Alice
	ksa := keys.NewMemKeyStore()
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err := ksa.SaveX25519Key(alice)
	require.NoError(t, err)

	// Bob
	ksb := keys.NewMemKeyStore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ksb.SaveX25519Key(bob)
	require.NoError(t, err)

	message := []byte("hi bob")

	encrypted, err := spa.Encrypt(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err := spb.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	encrypted2, err := spa.EncryptArmored(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err = spb.DecryptArmored(encrypted2)
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

	_, err = spa.Encrypt(message, alice, keys.ID(""))
	require.EqualError(t, err, "invalid recipient: empty id")

	// Duplicate recipient
	_, err = spa.Encrypt(message, alice, bob.ID(), bob.ID())
	require.NoError(t, err)
}

func TestEncryptAnon(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeyStore()
	spa := saltpack.NewSaltpack(ksa)

	// Bob
	ksb := keys.NewMemKeyStore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err := ksb.SaveX25519Key(bob)
	require.NoError(t, err)

	message := []byte("hi bob")
	// Anon sender
	encrypted, err := spa.Encrypt(message, nil, bob.ID())
	require.NoError(t, err)
	out, sender, err := spb.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Nil(t, sender)
}

func TestEncryptStream(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeyStore()
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.GenerateX25519Key()
	err := ksa.SaveX25519Key(alice)
	require.NoError(t, err)

	// Bob
	ksb := keys.NewMemKeyStore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.GenerateX25519Key()
	err = ksb.SaveX25519Key(bob)
	require.NoError(t, err)
	message := []byte("hi bob")

	var buf bytes.Buffer
	encrypted, err := spa.NewEncryptStream(&buf, alice, bob.ID())
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	stream, sender, err := spb.NewDecryptStream(&buf)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	var buf2 bytes.Buffer
	encrypted2, err := spa.NewEncryptArmoredStream(&buf2, alice, bob.ID())
	require.NoError(t, err)
	n, err = encrypted2.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted2.Close()

	stream, sender, err = spb.NewDecryptArmoredStream(&buf2)
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err = ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptStreamAnon(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeyStore()
	spa := saltpack.NewSaltpack(ksa)

	// Bob
	ksb := keys.NewMemKeyStore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.GenerateX25519Key()
	err := ksb.SaveX25519Key(bob)
	require.NoError(t, err)

	message := []byte("hi bob, its anon")

	// Anon sender
	var buf bytes.Buffer
	encrypted, err := spa.NewEncryptStream(&buf, nil, bob.ID())
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	stream, sender, err := spb.NewDecryptStream(&buf)
	require.NoError(t, err)
	require.Nil(t, sender)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptOpenError(t *testing.T) {
	ksa := keys.NewMemKeyStore()
	alice := keys.GenerateX25519Key()
	err := ksa.SaveX25519Key(alice)
	require.NoError(t, err)
	bob := keys.GenerateX25519Key()
	err = ksa.SaveX25519Key(bob)
	require.NoError(t, err)
	spa := saltpack.NewSaltpack(ksa)

	encrypted, err := spa.Encrypt([]byte("alice's message"), alice, bob.ID())
	require.NoError(t, err)

	ksb := keys.NewMemKeyStore()
	spb := saltpack.NewSaltpack(ksb)

	_, _, err = spb.Decrypt(encrypted)
	require.EqualError(t, err, "no decryption key found for message")
}

func TestEncryptWithEdX25519Key(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeyStore()
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err := ksa.SaveEdX25519Key(alice)
	require.NoError(t, err)

	// Bob
	ksb := keys.NewMemKeyStore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ksb.SaveEdX25519Key(bob)
	require.NoError(t, err)

	message := []byte("hi bob")

	encrypted, err := spa.Encrypt(message, alice.X25519Key(), bob.ID())
	require.NoError(t, err)

	out, sender, err := spb.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.X25519Key().PublicKey().ID(), sender.ID())
}
