package encoding_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func TestPhrase(t *testing.T) {
	b, err := encoding.PhraseToBytes("invalid phrase", false)
	require.EqualError(t, err, "invalid phrase")
	require.Nil(t, b)

	b, err = encoding.PhraseToBytes("shove quiz copper settle harvest victory shell fade soft neck awake churn craft venue pause utility service degree invite inspire swing detect pipe sibling", false)
	require.NoError(t, err)
	require.Equal(t, "c715fcbfe23697e7715a8ece527440946321e4e85f82c42739d83aadc078e956", hex.EncodeToString(b[:]))

	b, err = encoding.PhraseToBytes("shove quiz copper settle harvest victory shell fade soft neck awake churn", false)
	require.EqualError(t, err, "invalid phrase")
	require.EqualError(t, errors.Cause(err), "Invalid mnenomic")
	require.Nil(t, b)
}

func TestPhraseFromKey(t *testing.T) {
	key := randBytes(32)
	phrase, err := encoding.BytesToPhrase(key)
	require.NoError(t, err)
	keyOut, err := encoding.PhraseToBytes(phrase, false)
	require.NoError(t, err)
	require.Equal(t, key, keyOut[:])
}
