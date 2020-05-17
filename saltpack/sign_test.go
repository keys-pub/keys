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
	alice := keys.GenerateEdX25519Key()

	message := []byte("hi")

	sig, err := saltpack.Sign(message, alice)
	require.NoError(t, err)

	out, signer, err := saltpack.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), signer)

	sig, err = saltpack.SignDetached(message, alice)
	require.NoError(t, err)

	signer, err = saltpack.VerifyDetached(sig, message)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyArmored(t *testing.T) {
	alice := keys.GenerateEdX25519Key()

	message := []byte("hi")

	sig, err := saltpack.SignArmored(message, alice)
	require.NoError(t, err)

	messageOut, signer, err := saltpack.VerifyArmored(sig)
	require.NoError(t, err)
	require.Equal(t, message, messageOut)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyStream(t *testing.T) {
	alice := keys.GenerateEdX25519Key()

	message := []byte("I'm alice")

	var buf bytes.Buffer
	signed, err := saltpack.NewSignStream(&buf, alice)
	require.NoError(t, err)
	n, err := signed.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	signed.Close()

	reader := bytes.NewReader(buf.Bytes())
	stream, signer, err := saltpack.NewVerifyStream(reader)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	var buf2 bytes.Buffer
	signed2, err := saltpack.NewSignArmoredStream(&buf2, alice)
	require.NoError(t, err)
	n, err = signed2.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	signed2.Close()

	reader = bytes.NewReader(buf2.Bytes())
	stream, signer, err = saltpack.NewVerifyArmoredStream(reader)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
	out, err = ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	// Sign detached
	var buf3 bytes.Buffer
	signed3, err := saltpack.NewSignDetachedStream(&buf3, alice)
	require.NoError(t, err)
	_, err = signed3.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	signed3.Close()

	signer, err = saltpack.VerifyDetachedReader(buf3.Bytes(), bytes.NewReader(message))
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)

	// Sign armored/detached
	var buf4 bytes.Buffer
	signed4, err := saltpack.NewSignArmoredDetachedStream(&buf4, alice)
	require.NoError(t, err)
	_, err = signed4.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	signed4.Close()

	signer, err = saltpack.VerifyArmoredDetachedReader(buf4.String(), bytes.NewBuffer(message))
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestStripBefore(t *testing.T) {
	sig := "BEGIN SALTPACK SIGNED MESSAGE. XXXXXXXX END SALTPACK SIGNED MESSAGE."
	message := saltpack.StripBefore("Some text in the beginning to ignore: " + sig)
	require.Equal(t, sig, message)
}
