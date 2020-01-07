package saltpack

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyDefault(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	sp := NewSaltpack(nil)

	alice := keys.GenerateSignKey()

	message := []byte("hi")

	sig, err := sp.Sign(message, alice)
	require.NoError(t, err)

	messageOut, signer, err := sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, messageOut)
	require.Equal(t, alice.PublicKey().ID(), signer.ID())
}

func TestSignVerifyArmored(t *testing.T) {
	sp := NewSaltpack(nil)
	sp.SetArmored(true)
	alice := keys.GenerateSignKey()

	message := []byte("hi")

	sig, err := sp.Sign(message, alice)
	require.NoError(t, err)

	messageOut, signer, err := sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, messageOut)
	require.Equal(t, alice.PublicKey().ID(), signer.ID())

	// Verify with some prefix text
	armored2 := stripBefore("some prefix text: \n" + string(sig) + "some suffix text")
	messageOut2, _, err := sp.Verify([]byte(armored2))
	require.NoError(t, err)
	require.Equal(t, message, messageOut2)
}

func TestSignVerifyDetached(t *testing.T) {
	sp := NewSaltpack(nil)
	alice := keys.GenerateSignKey()

	message := []byte("hi")

	sig, err := sp.SignDetached(message, alice)
	require.NoError(t, err)

	signer, err := sp.VerifyDetached(sig, message)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer.ID())
}

func TestSignVerifyStream(t *testing.T) {
	sp := NewSaltpack(nil)
	alice := keys.GenerateSignKey()

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
	require.Equal(t, alice.PublicKey().ID(), signer.ID())
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestStrip(t *testing.T) {
	sig := "BEGIN SALTPACK SIGNED MESSAGE. XXXXXXXX END SALTPACK SIGNED MESSAGE."
	message := stripBefore("Some text in the beginning to ignore: " + sig)
	require.Equal(t, sig, message)
}
