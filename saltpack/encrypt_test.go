package saltpack_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err := ksa.SaveBoxKey(alice)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ksb.SaveBoxKey(bob)

	message := []byte("hi bob")

	encrypted, err := spa.Encrypt(message, alice, bob.ID())
	require.NoError(t, err)

	out, sender, err := spb.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), sender)

	_, err = spa.Encrypt(message, alice, keys.ID(""))
	require.EqualError(t, err, "invalid recipient: empty id")
}

func TestEncryptAnon(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := saltpack.NewSaltpack(ksa)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
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
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.GenerateX25519Key()
	err := ksa.SaveBoxKey(alice)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.GenerateX25519Key()
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
	spa := saltpack.NewSaltpack(ksa)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.GenerateX25519Key()
	err := ksb.SaveBoxKey(bob)
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
	require.Equal(t, keys.ID(""), sender)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptOpenError(t *testing.T) {
	ksa := keys.NewMemKeystore()
	alice := keys.GenerateX25519Key()
	err := ksa.SaveBoxKey(alice)
	bob := keys.GenerateX25519Key()
	err = ksa.SaveBoxKey(bob)
	require.NoError(t, err)
	spa := saltpack.NewSaltpack(ksa)

	encrypted, err := spa.Encrypt([]byte("alice's message"), alice, bob.ID())
	require.NoError(t, err)

	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)

	_, _, err = spb.Decrypt(encrypted)
	require.EqualError(t, err, "no decryption key found for message")
}

func TestEncryptWithEdX25519Key(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err := ksa.SaveSignKey(alice)
	require.NoError(t, err)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ksb.SaveSignKey(bob)
	require.NoError(t, err)

	message := []byte("hi bob")

	encrypted, err := spa.Encrypt(message, alice.X25519Key(), bob.ID())
	require.NoError(t, err)

	out, sender, err := spb.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.X25519Key().PublicKey().ID(), sender)
}

func ExampleSaltpack_Encrypt() {
	ks := keys.NewMemKeystore()
	sp := saltpack.NewSaltpack(ks)
	// For armored output
	sp.SetArmored(true)

	// Alice
	alice := keys.GenerateEdX25519Key()
	if err := ks.SaveSignKey(alice); err != nil {
		log.Fatal(err)
	}

	// Bob
	bob := keys.GenerateEdX25519Key()

	message := []byte("hi bob")

	// Encrypt from alice to bob
	encrypted, err := sp.Encrypt(message, alice.X25519Key(), bob.ID())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encrypted: %s", string(encrypted))
}

func ExampleSaltpack_Decrypt() {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.GenerateEdX25519Key()
	err := ksa.SaveSignKey(alice)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.GenerateEdX25519Key()
	err = ksb.SaveSignKey(bob)

	message := []byte("hi bob")

	// Encrypt from alice to bob
	encrypted, err := spa.Encrypt(message, alice.X25519Key(), bob.ID())
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt
	out, signer, err := spb.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signer: %s\n", signer)
	fmt.Printf("Decrypted: %s\n", string(out))
}
