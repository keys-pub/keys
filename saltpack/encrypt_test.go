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

	out, sender, err := saltpack.Decrypt(encrypted, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	encrypted2, err := saltpack.EncryptArmored(message, "TEST", alice, bob.ID())
	require.NoError(t, err)

	out, sender, brand, err := saltpack.DecryptArmored(encrypted2, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, "TEST", brand)
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
	out, sender, err := saltpack.Decrypt(encrypted, saltpack.NewKeyring(bob))
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
	stream, err := saltpack.NewEncryptStream(&buf, alice, bob.ID())
	require.NoError(t, err)
	n, err := stream.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	stream.Close()
	encrypted := copyBytes(buf.Bytes())

	dstream, sender, err := saltpack.NewDecryptStream(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	dstream, key, enc, armored, err := saltpack.NewReader(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, saltpack.EncryptEncoding, enc)
	require.False(t, armored)
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
	stream, err := saltpack.NewEncryptArmoredStream(&buf, "TEST", alice, bob.ID())
	require.NoError(t, err)
	n, err := stream.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	stream.Close()
	encrypted := copyBytes(buf.Bytes())

	dstream, sender, brand, err := saltpack.NewDecryptArmoredStream(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.Equal(t, "TEST", brand)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	dstream, key, enc, armored, err := saltpack.NewReader(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, saltpack.EncryptEncoding, enc)
	require.True(t, armored)
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
	stream, err := saltpack.NewEncryptStream(&buf, nil, bob.ID())
	require.NoError(t, err)
	n, err := stream.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	stream.Close()
	encrypted := copyBytes(buf.Bytes())

	dstream, sender, err := saltpack.NewDecryptStream(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Nil(t, sender)
	out, err := ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	dstream, key, enc, armored, err := saltpack.NewReader(bytes.NewReader(encrypted), saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Nil(t, key)
	require.Equal(t, saltpack.EncryptEncoding, enc)
	require.False(t, armored)
	out, err = ioutil.ReadAll(dstream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptOpenError(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	encrypted, err := saltpack.Encrypt([]byte("alice's message"), alice, bob.ID())
	require.NoError(t, err)

	_, _, err = saltpack.Decrypt(encrypted, saltpack.NewKeyring())
	require.EqualError(t, err, "no decryption key found for message")
}

func TestEncryptWithEdX25519Key(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	message := []byte("hi bob")

	encrypted, err := saltpack.Encrypt(message, alice.X25519Key(), bob.ID())
	require.NoError(t, err)

	out, sender, err := saltpack.Decrypt(encrypted, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.NotNil(t, sender)
	require.Equal(t, alice.X25519Key().PublicKey().ID(), sender.ID())
}

func TestReaderError(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	_, _, _, _, err := saltpack.NewReader(bytes.NewReader([]byte{0x01}), saltpack.NewKeyring(alice))
	require.EqualError(t, err, "invalid data")
}

func TestOpen(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	data := []byte("testdata")
	msg, err := saltpack.SigncryptArmored(data, "TEST", alice, bob.ID())
	require.NoError(t, err)

	kr := saltpack.NewKeyring(bob)
	out, sender, detected, err := saltpack.Open([]byte(msg), kr)
	require.NoError(t, err)
	require.Equal(t, saltpack.SigncryptEncoding, detected.Encoding)
	require.Equal(t, "TEST", detected.Brand)
	require.True(t, detected.Armored)
	require.Equal(t, alice.ID(), sender.ID())
	require.Equal(t, data, out)

}
