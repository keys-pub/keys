package saltpack_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/saltpack"
	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	// Alice
	ksa := keys.NewMemKeystore()
	spa := saltpack.NewSaltpack(ksa)
	alice := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err := ksa.SaveX25519Key(alice)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ksb.SaveX25519Key(bob)

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
	err := ksb.SaveX25519Key(bob)

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
	err := ksa.SaveX25519Key(alice)

	// Bob
	ksb := keys.NewMemKeystore()
	spb := saltpack.NewSaltpack(ksb)
	bob := keys.GenerateX25519Key()
	err = ksb.SaveX25519Key(bob)
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
	require.Equal(t, keys.ID(""), sender)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestEncryptOpenError(t *testing.T) {
	ksa := keys.NewMemKeystore()
	alice := keys.GenerateX25519Key()
	err := ksa.SaveX25519Key(alice)
	bob := keys.GenerateX25519Key()
	err = ksa.SaveX25519Key(bob)
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
	err := ksa.SaveEdX25519Key(alice)
	require.NoError(t, err)

	// Bob
	ksb := keys.NewMemKeystore()
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
	require.Equal(t, alice.X25519Key().PublicKey().ID(), sender)
}

func ExampleSaltpack_Encrypt() {
	sp := saltpack.NewSaltpack(nil)
	// For armored output
	sp.SetArmored(true)

	// Alice
	alice := keys.GenerateEdX25519Key()

	// Bob
	bob := keys.GenerateEdX25519Key()

	message := []byte("hi bob")

	// Encrypt from alice to bob
	encrypted, err := sp.Encrypt(message, alice.X25519Key(), bob.ID())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d", len(encrypted))
	// Output: 375
}

func ExampleSaltpack_Decrypt() {
	// Alice
	krAlice, err := keyring.NewKeyring("AliceKeyring")
	if err != nil {
		log.Fatal(err)
	}
	// Remove this Reset() if you want to keep the Keyring
	defer krAlice.Reset()
	if err := keyring.UnlockWithPassword(krAlice, "alicepassword"); err != nil {
		log.Fatal(err)
	}
	ksAlice := keys.NewKeystore(krAlice)
	spAlice := saltpack.NewSaltpack(ksAlice)
	alice := keys.GenerateEdX25519Key()
	if err := ksAlice.SaveEdX25519Key(alice); err != nil {
		log.Fatal(err)
	}

	// Bob
	krBob, err := keyring.NewKeyring("BobKeyring")
	if err != nil {
		log.Fatal(err)
	}
	// Remove this Reset() if you want to keep the Keyring
	defer krBob.Reset()
	if err := keyring.UnlockWithPassword(krBob, "bobpassword"); err != nil {
		log.Fatal(err)
	}
	ksBob := keys.NewKeystore(krBob)
	spBob := saltpack.NewSaltpack(ksBob)
	bob := keys.GenerateEdX25519Key()
	if err = ksBob.SaveEdX25519Key(bob); err != nil {
		log.Fatal(err)
	}

	message := []byte("hi bob")

	// Alice encrypt's to bob (and alice)
	encrypted, err := spAlice.Encrypt(message, alice.X25519Key(), bob.ID(), alice.ID())
	if err != nil {
		log.Fatal(err)
	}

	// Bob decrypt's
	out, signer, err := spBob.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	if signer == alice.X25519Key().ID() {
		fmt.Printf("Signer is alice\n")
	}
	fmt.Printf("%s\n", string(out))

	// Alice can decrypt too
	out, signer, err = spAlice.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	if signer == alice.X25519Key().ID() {
		fmt.Printf("Signer is alice\n")
	}
	fmt.Printf("%s\n", string(out))

	// Output:
	// Signer is alice
	// hi bob
	// Signer is alice
	// hi bob
}
