package saltpack

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := NewSaltpack(ksa)
	alice := keys.NewCurve25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err := ksa.SaveBoxKey(alice)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	bob := keys.NewCurve25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ksb.SaveBoxKey(bob)

	message := []byte("hi bob")

	encrypted, err := spa.Encrypt(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err := spb.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), sender)

	_, err = spa.Encrypt(message, alice, keys.ID(""))
	require.EqualError(t, err, "invalid recipient: empty")
}

func TestEncryptAnon(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := NewSaltpack(ksa)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	bob := keys.NewCurve25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err := ksb.SaveBoxKey(bob)

	message := []byte("hi bob")
	// Anon sender
	encrypted, err := spa.Encrypt(message, nil, bob.ID())
	require.NoError(t, err)
	out, sender, err := spb.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, keys.ID(""), sender)
}

func TestEncryptStream(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := NewSaltpack(ksa)
	alice := keys.GenerateCurve25519Key()
	err := ksa.SaveBoxKey(alice)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	bob := keys.GenerateCurve25519Key()
	err = ksb.SaveBoxKey(bob)
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
	require.Equal(t, alice.PublicKey().ID(), sender)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

}

func TestEncryptStreamAnon(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := NewSaltpack(ksa)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	bob := keys.GenerateCurve25519Key()
	err := ksb.SaveBoxKey(bob)

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
	require.Equal(t, keys.ID(""), sender)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptOpenError(t *testing.T) {
	ksa := keys.NewMemKeystore()
	alice := keys.GenerateCurve25519Key()
	err := ksa.SaveBoxKey(alice)
	bob := keys.GenerateCurve25519Key()
	err = ksa.SaveBoxKey(bob)
	require.NoError(t, err)
	spa := NewSaltpack(ksa)

	encrypted, err := spa.Encrypt([]byte("alice's message"), alice, bob.ID())
	require.NoError(t, err)

	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)

	_, _, err = spb.Decrypt(encrypted)
	require.EqualError(t, err, "no decryption key found for message")
}

func TestEncryptWithEd25519Key(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := NewSaltpack(ksa)
	alice := keys.NewEd25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err := ksa.SaveSignKey(alice)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	bob := keys.NewEd25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ksb.SaveSignKey(bob)

	message := []byte("hi bob")

	encrypted, err := spa.Encrypt(message, alice.Curve25519Key(), bob.ID())
	require.NoError(t, err)

	out, sender, err := spb.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.Curve25519Key().PublicKey().ID(), sender)
}
