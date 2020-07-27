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

	encrypted, err := saltpack.Encrypt(message, false, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err := saltpack.Decrypt(encrypted, false, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	encrypted2, err := saltpack.Encrypt(message, true, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err = saltpack.Decrypt([]byte(encrypted2), true, saltpack.NewKeyring(bob))
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

	_, err = saltpack.Encrypt(message, false, alice, keys.ID(""))
	require.EqualError(t, err, "invalid recipient: empty id")

	// Duplicate recipient
	_, err = saltpack.Encrypt(message, false, alice, bob.ID(), bob.ID())
	require.NoError(t, err)
}

func TestEncryptAnon(t *testing.T) {
	bob := keys.NewX25519KeyFromSeed(testSeed(0x02))
	message := []byte("hi bob")
	// Anon sender
	encrypted, err := saltpack.Encrypt(message, false, nil, bob.ID())
	require.NoError(t, err)
	out, sender, err := saltpack.Decrypt(encrypted, false, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Nil(t, sender)
}

func copyBytes(source []byte) []byte {
	dest := make([]byte, len(source))
	copy(dest, source)
	return dest
}

func TestEncryptStream(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()
	message := []byte("hi bob")

	var buf bytes.Buffer
	stream, err := saltpack.NewEncryptStream(&buf, false, alice, bob.ID())
	require.NoError(t, err)
	n, err := stream.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	stream.Close()
	encrypted := copyBytes(buf.Bytes())

	dstream, sender, err := saltpack.NewDecryptStream(bytes.NewReader(encrypted), false, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	dstream, key, enc, err := saltpack.NewReader(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, saltpack.EncryptEncoding, enc)
	require.Equal(t, alice.PublicKey().ID(), key.ID())
	out, err = ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptArmoredStream(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()
	message := []byte("hi bob")

	var buf bytes.Buffer
	stream, err := saltpack.NewEncryptStream(&buf, true, alice, bob.ID())
	require.NoError(t, err)
	n, err := stream.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	stream.Close()
	encrypted := copyBytes(buf.Bytes())

	dstream, sender, err := saltpack.NewDecryptStream(bytes.NewReader(encrypted), true, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	dstream, key, enc, err := saltpack.NewReader(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, saltpack.EncryptEncoding, enc)
	require.Equal(t, alice.PublicKey().ID(), key.ID())
	out, err = ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptStreamAnon(t *testing.T) {
	bob := keys.GenerateX25519Key()
	message := []byte("hi bob, its anon")

	// Anon sender
	var buf bytes.Buffer
	stream, err := saltpack.NewEncryptStream(&buf, false, nil, bob.ID())
	require.NoError(t, err)
	n, err := stream.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	stream.Close()
	encrypted := copyBytes(buf.Bytes())

	dstream, sender, err := saltpack.NewDecryptStream(bytes.NewReader(encrypted), false, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Nil(t, sender)
	out, err := ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	dstream, key, enc, err := saltpack.NewReader(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Nil(t, key)
	if key != nil {
		t.Fatal("not nil")
	}
	require.Equal(t, saltpack.EncryptEncoding, enc)
	out, err = ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptOpenError(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	encrypted, err := saltpack.Encrypt([]byte("alice's message"), false, alice, bob.ID())
	require.NoError(t, err)

	_, _, err = saltpack.Decrypt(encrypted, false, saltpack.NewKeyring())
	require.EqualError(t, err, "no decryption key found for message")
}

func TestEncryptWithEdX25519Key(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	message := []byte("hi bob")

	encrypted, err := saltpack.Encrypt(message, false, alice.X25519Key(), bob.ID())
	require.NoError(t, err)

	out, sender, err := saltpack.Decrypt(encrypted, false, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.X25519Key().PublicKey().ID(), sender.ID())
}
