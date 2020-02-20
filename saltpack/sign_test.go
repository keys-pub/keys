package saltpack_test

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	sp := saltpack.NewSaltpack(nil)

	alice := keys.GenerateEdX25519Key()

	message := []byte("hi")

	sig, err := sp.Sign(message, alice)
	require.NoError(t, err)

	messageOut, signer, err := sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, messageOut)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func ExampleSaltpack_Sign() {
	ks := keys.NewKeystore()
	sp := saltpack.NewSaltpack(ks)
	sp.SetArmored(true)

	alice := keys.GenerateEdX25519Key()

	message := []byte("hi from alice")

	sig, err := sp.Sign(message, alice)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signed: %s", string(sig))
}

func ExampleSaltpack_SignDetached() {
	ks := keys.NewKeystore()
	sp := saltpack.NewSaltpack(ks)
	sp.SetArmored(true)

	alice := keys.GenerateEdX25519Key()

	message := []byte("hi from alice")

	sig, err := sp.SignDetached(message, alice)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signed (detached): %s", string(sig))
}

func ExampleSaltpack_Verify() {
	ks := keys.NewKeystore()
	sp := saltpack.NewSaltpack(ks)
	sp.SetArmored(true)

	alice := keys.GenerateEdX25519Key()

	message := []byte("hi from alice")

	sig, err := sp.Sign(message, alice)
	if err != nil {
		log.Fatal(err)
	}

	out, signer, err := sp.Verify(sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signer: %s\n", signer)
	fmt.Printf("Out: %s\n", string(out))
}

func TestSignVerifyArmored(t *testing.T) {
	sp := saltpack.NewSaltpack(nil)
	sp.SetArmored(true)
	alice := keys.GenerateEdX25519Key()

	message := []byte("hi")

	sig, err := sp.Sign(message, alice)
	require.NoError(t, err)

	messageOut, signer, err := sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, messageOut)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyDetached(t *testing.T) {
	sp := saltpack.NewSaltpack(nil)
	alice := keys.GenerateEdX25519Key()

	message := []byte("hi")

	sig, err := sp.SignDetached(message, alice)
	require.NoError(t, err)

	signer, err := sp.VerifyDetached(sig, message)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyStream(t *testing.T) {
	sp := saltpack.NewSaltpack(nil)
	alice := keys.GenerateEdX25519Key()

	message := []byte("I'm alice")

	var buf bytes.Buffer
	encrypted, err := sp.NewSignStream(&buf, alice, false)
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	var reader io.Reader = bytes.NewReader(buf.Bytes())
	stream, signer, err := sp.NewVerifyStream(reader)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestStripBefore(t *testing.T) {
	sig := "BEGIN SALTPACK SIGNED MESSAGE. XXXXXXXX END SALTPACK SIGNED MESSAGE."
	message := saltpack.StripBefore("Some text in the beginning to ignore: " + sig)
	require.Equal(t, sig, message)
}
