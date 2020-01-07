package saltpack

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestSigncrypt(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	alice := keys.GenerateSignKey()
	err := ksa.SaveSignKey(alice)
	abk := keys.GenerateBoxKey()
	err = ksa.SaveBoxKey(abk)
	require.NoError(t, err)
	spa := NewSaltpack(ksa)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	bob := keys.GenerateSignKey()
	err = ksb.SaveSignKey(bob)
	bbk := keys.GenerateBoxKey()
	err = ksb.SaveBoxKey(bbk)
	require.NoError(t, err)

	message := []byte("hi bob")

	encrypted, err := spa.Signcrypt(message, alice, bbk.PublicKey())
	require.NoError(t, err)

	out, sender, err := spb.SigncryptOpen(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())

	_, err = spa.Signcrypt(message, alice, nil)
	require.EqualError(t, err, "nil recipient")
}

func TestSigncryptStream(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	alice := keys.GenerateSignKey()
	err := ksa.SaveSignKey(alice)
	abk := keys.GenerateBoxKey()
	err = ksa.SaveBoxKey(abk)
	require.NoError(t, err)
	spa := NewSaltpack(ksa)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	bob := keys.GenerateSignKey()
	err = ksb.SaveSignKey(bob)
	bbk := keys.GenerateBoxKey()
	err = ksb.SaveBoxKey(bbk)
	require.NoError(t, err)

	message := []byte("hi bob")

	var buf bytes.Buffer
	encrypted, err := spa.NewSigncryptStream(&buf, alice, bbk.PublicKey())
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	stream, sender, err := spb.NewSigncryptOpenStream(&buf)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), sender.ID())
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestSigncryptOpenError(t *testing.T) {
	ksa := keys.NewMemKeystore()
	alice := keys.GenerateSignKey()
	err := ksa.SaveSignKey(alice)
	abk := keys.GenerateBoxKey()
	err = ksa.SaveBoxKey(abk)
	require.NoError(t, err)
	spa := NewSaltpack(ksa)

	encrypted, err := spa.Signcrypt([]byte("alice's message"), alice, abk.PublicKey())
	require.NoError(t, err)

	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)

	_, _, err = spb.SigncryptOpen(encrypted)
	require.EqualError(t, err, "no decryption key found for message")
}
