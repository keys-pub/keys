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
	clock := newClock()
	scs := keys.NewSigchainStore(keys.NewMem())
	ks := keys.NewMemKeystore()
	ks.SetSigchainStore(scs)
	sp := NewSaltpack(ks)
	alice, err := ks.GenerateKey(true, clock.Now())
	require.NoError(t, err)

	message := []byte("hi")

	sig, err := sp.Sign(message, alice.SignKey())
	require.NoError(t, err)

	messageOut, signer, err := sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, messageOut)
	require.Equal(t, alice.ID(), keys.SignPublicKeyID(signer))
}

func TestSignVerifyArmored(t *testing.T) {
	clock := newClock()
	scs := keys.NewSigchainStore(keys.NewMem())
	ks := keys.NewMemKeystore()
	ks.SetSigchainStore(scs)
	sp := NewSaltpack(ks)
	sp.SetArmored(true)
	alice, err := ks.GenerateKey(true, clock.Now())
	require.NoError(t, err)

	message := []byte("hi")

	sig, err := sp.Sign(message, alice.SignKey())
	require.NoError(t, err)

	messageOut, signer, err := sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, messageOut)
	require.Equal(t, alice.ID(), keys.SignPublicKeyID(signer))

	// Verify with some prefix text
	armored2 := stripBefore("some prefix text: \n" + string(sig) + "some suffix text")
	messageOut2, _, err := sp.Verify([]byte(armored2))
	require.NoError(t, err)
	require.Equal(t, message, messageOut2)
}

func TestSignVerifyDetached(t *testing.T) {
	clock := newClock()
	scs := keys.NewSigchainStore(keys.NewMem())
	ks := keys.NewMemKeystore()
	ks.SetSigchainStore(scs)
	sp := NewSaltpack(ks)
	alice, err := ks.GenerateKey(true, clock.Now())
	require.NoError(t, err)

	message := []byte("hi")

	sig, err := sp.SignDetached(message, alice.SignKey())
	require.NoError(t, err)

	signer, err := sp.VerifyDetached(sig, message)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), keys.SignPublicKeyID(signer))
}

func TestSignVerifyStream(t *testing.T) {
	clock := newClock()
	scs := keys.NewSigchainStore(keys.NewMem())
	ks := keys.NewMemKeystore()
	ks.SetSigchainStore(scs)
	alice, err := ks.GenerateKey(true, clock.Now())
	require.NoError(t, err)
	sp := NewSaltpack(ks)

	message := []byte("I'm alice")

	var buf bytes.Buffer
	encrypted, err := sp.NewSignStream(&buf, alice.SignKey(), false)
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	var reader io.Reader = bytes.NewReader(buf.Bytes())
	stream, signer, err := sp.NewVerifyStream(reader)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), keys.SignPublicKeyID(signer))
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func TestStrip(t *testing.T) {
	sig := "BEGIN SALTPACK SIGNED MESSAGE. XXXXXXXX END SALTPACK SIGNED MESSAGE."
	message := stripBefore("Some text in the beginning to ignore: " + sig)
	require.Equal(t, sig, message)
}
