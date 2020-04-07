package saltpack_test

import (
	"bytes"
	"io/ioutil"
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

	out, signer, err := sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), signer)

	sig, err = sp.SignDetached(message, alice)
	require.NoError(t, err)

	signer, err = sp.VerifyDetached(sig, message)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyArmored(t *testing.T) {
	sp := saltpack.NewSaltpack(nil)
	alice := keys.GenerateEdX25519Key()

	message := []byte("hi")

	sig, err := sp.SignArmored(message, alice)
	require.NoError(t, err)

	messageOut, signer, err := sp.VerifyArmored(sig)
	require.NoError(t, err)
	require.Equal(t, message, messageOut)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyStream(t *testing.T) {
	sp := saltpack.NewSaltpack(nil)
	alice := keys.GenerateEdX25519Key()

	message := []byte("I'm alice")

	var buf bytes.Buffer
	signed, err := sp.NewSignStream(&buf, alice, false)
	require.NoError(t, err)
	n, err := signed.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	signed.Close()

	reader := bytes.NewReader(buf.Bytes())
	stream, signer, err := sp.NewVerifyStream(reader)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	var buf2 bytes.Buffer
	signed2, err := sp.NewSignArmoredStream(&buf2, alice, false)
	require.NoError(t, err)
	n, err = signed2.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	signed2.Close()

	reader = bytes.NewReader(buf2.Bytes())
	stream, signer, err = sp.NewVerifyArmoredStream(reader)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
	out, err = ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestStripBefore(t *testing.T) {
	sig := "BEGIN SALTPACK SIGNED MESSAGE. XXXXXXXX END SALTPACK SIGNED MESSAGE."
	message := saltpack.StripBefore("Some text in the beginning to ignore: " + sig)
	require.Equal(t, sig, message)
}
