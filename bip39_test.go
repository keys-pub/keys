package keys

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestPhrase(t *testing.T) {
	b, err := PhraseToBytes("invalid phrase", false)
	require.EqualError(t, err, "invalid phrase")
	require.Nil(t, b)

	b, err = PhraseToBytes("shove quiz copper settle harvest victory shell fade soft neck awake churn craft venue pause utility service degree invite inspire swing detect pipe sibling", false)
	require.NoError(t, err)
	require.Equal(t, "c715fcbfe23697e7715a8ece527440946321e4e85f82c42739d83aadc078e956", hex.EncodeToString(b[:]))

	b, err = PhraseToBytes("shove quiz copper settle harvest victory shell fade soft neck awake churn", false)
	require.EqualError(t, err, "invalid phrase")
	require.EqualError(t, errors.Cause(err), "Checksum incorrect")
	require.Nil(t, b)
}

func TestPhraseFromKey(t *testing.T) {
	key := RandKey()[:]
	phrase, err := BytesToPhrase(key)
	require.NoError(t, err)
	keyOut, err := PhraseToBytes(phrase, false)
	require.NoError(t, err)
	require.Equal(t, key, keyOut[:])
}

func TestSeedPhrase(t *testing.T) {
	signKey := GenerateSignKey()
	phrase := signKey.SeedPhrase()
	require.NotEqual(t, "", phrase)

	signKeyOut, err := NewSignKeyFromSeedPhrase(phrase, false)
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey(), signKeyOut.PrivateKey())

	phrase2 := "   " + strings.Join(strings.Split(phrase, " "), "   ") + "  "
	signKeyOut2, err := NewSignKeyFromSeedPhrase(phrase2, true)
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey(), signKeyOut2.PrivateKey())
}
