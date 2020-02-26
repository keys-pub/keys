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

	encrypted2, err := spa.EncryptArmored(message, "", alice, bob.ID())
	require.NoError(t, err)

	out, sender, err = spb.DecryptArmored(encrypted2)
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

	var buf2 bytes.Buffer
	encrypted2, err := spa.NewEncryptArmoredStream(&buf2, "", alice, bob.ID())
	require.NoError(t, err)
	n, err = encrypted2.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted2.Close()

	stream, sender, err = spb.NewDecryptArmoredStream(&buf2)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), sender)
	out, err = ioutil.ReadAll(stream)
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

	// Alice
	alice := keys.GenerateEdX25519Key()

	// Bob
	bobID := keys.ID("kex1yy7amjzd5ld3k0uphvyetlz2vd8yy3fky64dut9jdf9qh852f0nsxjgv0m")

	message := []byte("hi bob")

	// Encrypt from alice to bob
	encrypted, err := sp.EncryptArmored(message, "", alice.X25519Key(), bobID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d", len(encrypted))
	// Output: 375
}

func ExampleSaltpack_Decrypt() {
	// Message from Alice
	aliceID := keys.ID("kex1vrpxw9rqmf49kygc7ujjrdlx8lkzaarjc3s24j73xlqxhwvsyx2sw06r82")
	encrypted := `BEGIN SALTPACK ENCRYPTED MESSAGE. 
	kcJn5brvybfNjz6 D5ll2Nk0YusOJBf 9x1CB6V3o7cdMOV ZPenXvEVhLpMBj0 8rJiM2GJTyXbhDn 
	cGIoczvWtRoxL5r 3EIPrfVqpwhLDke LfCV6YykdYdGwY1 lUfrzkOIUGdeURb HDSwgrTSrcexwj3 
	ix9Mw1FVXQGBwBV yil8lLyD1q0VFGv KmgJYyARppqQEIF HgAsZq0BJL6Dosz WGrFalmG90QA6PO 
	avDlwRXMDbjKFvE wQtaBDKXVSBaM9k 0Xu0CfdGUkEICbN vZNV67cGqEz2IiH kr8. 
	END SALTPACK ENCRYPTED MESSAGE.`

	// Bob creates a Keyring and Keystore
	kr, err := keyring.NewKeyring("BobKeyring")
	if err != nil {
		log.Fatal(err)
	}
	// Remove this Reset() if you want to keep the Keyring
	defer kr.Reset()
	if err := keyring.UnlockWithPassword(kr, "bobpassword"); err != nil {
		log.Fatal(err)
	}
	ks := keys.NewKeystore(kr)
	sp := saltpack.NewSaltpack(ks)

	kmsg := `BEGIN EDX25519 KEY MESSAGE.
	E9zL57KzBY1CIdJ d5tlpnyCIX8R5DB oLswy2g17kbfK4s CwryRUoII3ZNk3l
	scLQrPmgNuKi9OK 7ugGoVWBY2n5xbK 7w500Vp2iXo6LAe XZiB06UjUdCoYJv
	YjKbul2B61uxTZc waeBgRV91RZoKCn xLQnRhLXE2KC.
	END EDX25519 KEY MESSAGE.`
	bob, err := keys.DecodeKeyFromSaltpack(kmsg, "password", false)
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.SaveKey(bob); err != nil {
		log.Fatal(err)
	}

	// Bob decrypt's
	out, signer, err := sp.DecryptArmored(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	// The signer from Saltpack Decrypt is a x25519 ID, so compare using
	// keys.PublicKeyIDEquals.
	if keys.PublicKeyIDEquals(aliceID, signer) {
		fmt.Printf("signer is alice\n")
	}
	fmt.Printf("%s\n", string(out))

	// Output:
	// signer is alice
	// hi bob
}
