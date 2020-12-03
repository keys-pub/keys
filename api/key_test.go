package api_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/saltpack"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKey(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0xef))
	key := api.NewKey(sk)

	require.Equal(t, sk.ID(), key.ID)
	require.Equal(t, sk.Private(), key.Private)
	require.Equal(t, sk.Public(), key.Public)
	require.Equal(t, "edx25519", key.Type)

	require.Equal(t, sk, key.AsEdX25519())
	require.Equal(t, sk.X25519Key(), key.AsX25519())
}

func TestNewKeyPublic(t *testing.T) {
	spk := keys.NewEdX25519KeyFromSeed(testSeed(0xef)).PublicKey()
	key := api.NewKey(spk)

	require.Equal(t, spk.ID(), key.ID)
	require.Equal(t, spk.Bytes(), key.Public)
	require.Nil(t, spk.Private())
	require.Equal(t, "edx25519", key.Type)

	require.Equal(t, spk, key.AsEdX25519Public())
}

func TestNewKeyX25519(t *testing.T) {
	sk := keys.NewX25519KeyFromSeed(testSeed(0x01))
	key := api.NewKey(sk)

	require.Equal(t, sk.ID(), key.ID)
	require.Equal(t, sk.Private(), key.Private)
	require.Equal(t, sk.Public(), key.Public)
	require.Equal(t, "x25519", key.Type)

	require.Equal(t, sk, key.AsX25519())
	require.Nil(t, key.AsEdX25519())
}

func TestNewKeyX25519Public(t *testing.T) {
	spk := keys.NewX25519KeyFromSeed(testSeed(0x01)).PublicKey()
	key := api.NewKey(spk)

	require.Equal(t, spk.ID(), key.ID)
	require.Equal(t, spk.Bytes(), key.Public)
	require.Nil(t, spk.Private())
	require.Equal(t, "x25519", key.Type)

	require.Equal(t, spk, key.AsX25519Public())
}

func TestEncryptKey(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0xef)))
	key.Notes = "some test notes"
	key.CreatedAt = clock.NowMillis()
	key.UpdatedAt = clock.NowMillis()

	out, err := api.EncryptKey(key, alice, bob.ID())
	require.NoError(t, err)

	dec, pk, err := api.DecryptKey(out, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, alice.ID(), pk.ID())
	assert.ObjectsAreEqual(dec, key)

	_, _, err = api.DecryptKey(out, saltpack.NewKeyring())
	require.EqualError(t, err, "no decryption key found for message")
}

func TestEncryptKeyWithPassword(t *testing.T) {
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0xef)))
	key.Notes = "some test notes"
	key.CreatedAt = clock.NowMillis()
	key.UpdatedAt = clock.NowMillis()

	out, err := api.EncryptKeyWithPassword(key, "testpassword")
	require.NoError(t, err)

	dec, err := api.DecryptKeyWithPassword(out, "testpassword")
	require.NoError(t, err)
	assert.ObjectsAreEqual(dec, key)

	// TODO: Invalid password error
	_, err = api.DecryptKeyWithPassword(out, "invalidpassword")
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
