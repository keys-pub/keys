package saltpack_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unicode/utf8"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	alice := keys.GenerateEdX25519Key()

	message := []byte("hi")

	sig, err := saltpack.Sign(message, false, alice)
	require.NoError(t, err)

	out, signer, err := saltpack.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), signer)

	sig, err = saltpack.SignDetached(message, false, alice)
	require.NoError(t, err)

	signer, err = saltpack.VerifyDetached(sig, message)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyArmored(t *testing.T) {
	alice := keys.GenerateEdX25519Key()

	message := []byte("hi")

	sig, err := saltpack.Sign(message, true, alice)
	require.NoError(t, err)

	out, signer, err := saltpack.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), signer)

	sig, err = saltpack.SignDetached(message, true, alice)
	require.NoError(t, err)

	signer, err = saltpack.VerifyDetached(sig, message)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyStream(t *testing.T) {
	alice := keys.GenerateEdX25519Key()

	message := []byte("I'm alice")

	var buf bytes.Buffer
	signed, err := saltpack.NewSignStream(&buf, false, false, alice)
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
	signed2, err := saltpack.NewSignStream(&buf2, true, false, alice)
	require.NoError(t, err)
	n, err = signed2.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	signed2.Close()

	reader = bytes.NewReader(buf2.Bytes())
	stream, signer, err = saltpack.NewVerifyStream(reader)
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
	out, err = ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)

	// Sign detached
	var buf3 bytes.Buffer
	signed3, err := saltpack.NewSignStream(&buf3, false, true, alice)
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
	signed4, err := saltpack.NewSignStream(&buf4, true, true, alice)
	require.NoError(t, err)
	_, err = signed4.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	signed4.Close()

	signer, err = saltpack.VerifyDetachedReader(buf4.Bytes(), bytes.NewBuffer(message))
	require.NoError(t, err)
	require.Equal(t, alice.PublicKey().ID(), signer)
}

func TestSignVerifyFile(t *testing.T) {
	testSignVerifyFile(t, false)
	testSignVerifyFile(t, true)
}

func testSignVerifyFile(t *testing.T, armored bool) {
	var err error
	alice := keys.GenerateEdX25519Key()
	in := filepath.Join(os.TempDir(), keys.RandFileName())
	data := bytes.Repeat([]byte{0x01}, 16*1024)
	err = ioutil.WriteFile(in, data, 0600)
	require.NoError(t, err)
	out := in + ".signed"
	outVerified := in + ".verified"
	defer func() {
		_ = os.Remove(in)
		_ = os.Remove(out)
		_ = os.Remove(outVerified)
	}()

	err = saltpack.SignFile(in, out, alice, armored, false)
	require.NoError(t, err)

	if armored {
		signed, err := ioutil.ReadFile(out)
		require.NoError(t, err)
		require.True(t, utf8.Valid(signed))
	}

	kid, err := saltpack.VerifyFile(out, outVerified)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), kid)
	b, err := ioutil.ReadFile(outVerified)
	require.NoError(t, err)
	require.Equal(t, data, b)
}

func TestSignFileErrors(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip()
	}
	var err error
	alice := keys.GenerateEdX25519Key()
	err = saltpack.SignFile("notfound", "notfound.sig", alice, true, true)
	require.EqualError(t, err, "open notfound: no such file or directory")
}

func TestVerifyFileErrors(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip()
	}
	var err error
	_, err = saltpack.VerifyFile("notfound.signed", "notfound")
	require.EqualError(t, err, "open notfound.signed: no such file or directory")
}

func TestSignVerifyFileDetached(t *testing.T) {
	testSignVerifyFileDetached(t, false)
	testSignVerifyFileDetached(t, true)
}

func testSignVerifyFileDetached(t *testing.T, armored bool) {
	var err error
	alice := keys.GenerateEdX25519Key()
	in := filepath.Join(os.TempDir(), keys.RandFileName())
	data := bytes.Repeat([]byte{0x01}, 16*1024)
	err = ioutil.WriteFile(in, data, 0600)
	require.NoError(t, err)
	out := in + ".sig"
	defer func() {
		_ = os.Remove(in)
		_ = os.Remove(out)
	}()

	err = saltpack.SignFile(in, out, alice, armored, true)
	require.NoError(t, err)

	sig, err := ioutil.ReadFile(out)
	require.NoError(t, err)

	if armored {
		require.True(t, utf8.Valid(sig))
	}

	kid, err := saltpack.VerifyFileDetached(sig, in)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), kid)
}

func TestStripBefore(t *testing.T) {
	sig := "BEGIN SALTPACK SIGNED MESSAGE. XXXXXXXX END SALTPACK SIGNED MESSAGE."
	message := saltpack.StripBefore("Some text in the beginning to ignore: " + sig)
	require.Equal(t, sig, message)
}
