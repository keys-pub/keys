package keys

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyDerive(t *testing.T) {
	seed := Bytes32(bytes.Repeat([]byte{0x01}, 32))
	key, err := NewKey(seed)
	require.NoError(t, err)
	// These match up with output from Keybase:
	// seed := libkb.PerKeySeed(libkb.MakeByte32(bytes.Repeat([]byte{0x01}, 32)))
	// sk, err := seed.DeriveSigningKey()
	// fmt.Printf("pk: %s\n", hex.EncodeToString(sk.Public[:]))
	// fmt.Printf("sk: %s\n", hex.EncodeToString(sk.Private[:]))
	require.Equal(t, "80f32862bf4967f44d2aec1854817f28daf4a6457afae65e628f0edadc76f240", hex.EncodeToString(key.SignKey().PublicKey[:]))
	require.Equal(t, "e711192f3f10aa07c4e9680c0c494b9bf3aa07599fe3970ddca5247608b975e180f32862bf4967f44d2aec1854817f28daf4a6457afae65e628f0edadc76f240", hex.EncodeToString(key.SignKey().privateKey[:]))

	// sk, err := seed.DeriveDHKey()
	// fmt.Printf("pk: %s\n", hex.EncodeToString(sk.Public[:]))
	// fmt.Printf("sk: %s\n", hex.EncodeToString(sk.Private[:]))
	require.Equal(t, "7e018699a94b85e512e5315ad676ead4801124470314e18eee72d930e7f8ff5f", hex.EncodeToString(key.BoxKey().PublicKey[:]))
	require.Equal(t, "7ea271fd4983c318e6873bf48c5bc914c01aa9bda8ab1e47abb183869b583668", hex.EncodeToString(key.BoxKey().privateKey[:]))

	// sk, err := seed.DeriveSymmetricKey(libkb.DeriveReasonPUKPrev)
	// fmt.Printf("k: %s\n", hex.EncodeToString(sk[:]))
	require.Equal(t, "6f15f7ebc3e2a78d636b64b55122b881b95ef46696c7adcf3a886a91d4855c5e", hex.EncodeToString(key.SecretKey()[:]))
}

func TestKeyGenerateSeedBytes(t *testing.T) {
	key := GenerateKey()

	phrase := SeedPhrase(key)
	keyOut, err := NewKeyFromSeedPhrase(phrase, false)
	require.NoError(t, err)

	require.Equal(t, key.BoxKey().privateKey[:], keyOut.BoxKey().privateKey[:])
	require.Equal(t, key.SignKey().privateKey[:], keyOut.SignKey().privateKey[:])
}

func TestNewKeyFromPassword(t *testing.T) {
	salt := bytes.Repeat([]byte{0x01}, 32)
	_, err := NewKeyFromPassword("password", salt)
	require.EqualError(t, err, "password too short")

	key, err := NewKeyFromPassword("password123", salt)
	require.NoError(t, err)
	require.Equal(t, "c5b09a019c71738183a4b90bd18fe09f2a52a20380df2f10277288dcc5f40f94", hex.EncodeToString(key.SecretKey()[:]))
}

func TestKey(t *testing.T) {
	clock := newClock()
	ks := NewMemKeystore()

	key := GenerateKey()
	require.NotNil(t, key)

	err := ks.SaveKey(key, false, clock.Now())
	require.NoError(t, err)

	keyOut, err := ks.Key(key.ID())
	require.NotNil(t, keyOut)
	require.NoError(t, err)

	require.Equal(t, key.BoxKey().privateKey[:], keyOut.BoxKey().privateKey[:])
	require.Equal(t, key.SignKey().privateKey[:], keyOut.SignKey().privateKey[:])

	keys, err := ks.Keys()
	require.NoError(t, err)
	require.Equal(t, 1, len(keys))
	require.Equal(t, key.ID(), keys[0].ID())
}

type testVector struct {
	key      string
	msg      string
	expected string
	truncate int
}

func TestHMACSHA256(t *testing.T) {
	vectors := []testVector{
		testVector{
			key:      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			msg:      "4869205468657265",
			expected: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		testVector{
			key:      "4a656665",
			msg:      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
		testVector{
			key:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			msg:      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			expected: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		},
		testVector{
			key:      "0102030405060708090a0b0c0d0e0f10111213141516171819",
			msg:      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
			expected: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
		},
		testVector{
			key:      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
			msg:      "546573742057697468205472756e636174696f6e",
			expected: "a3b6167473100ee06e0c796c2955552b",
			truncate: 16,
		},
		testVector{
			key:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			msg:      "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
			expected: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		},
		testVector{
			key:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			msg:      "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
			expected: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
		},
	}

	for _, v := range vectors {
		key, err := hex.DecodeString(v.key)
		require.NoError(t, err)
		msg, err := hex.DecodeString(v.msg)
		require.NoError(t, err)
		out := HMACSHA256(key, msg)
		expected, err := hex.DecodeString(v.expected)
		require.NoError(t, err)
		if v.truncate > 0 {
			out = out[0:v.truncate]
		}
		require.Equal(t, expected, out)
	}
}
