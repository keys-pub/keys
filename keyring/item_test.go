package keyring

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestItem(t *testing.T) {
	secretKey := randKey()
	item := NewItem("account1", NewStringSecret("password"), "passphrase")
	item.SetSecretFor("website", NewStringSecret("keys.app"))
	b, err := item.Marshal(secretKey)
	require.NoError(t, err)

	_, err = item.Marshal(nil)
	require.EqualError(t, err, "no secret key specified")

	itemOut, err := DecodeItem(b, secretKey)
	require.NoError(t, err)

	require.Equal(t, item.ID, itemOut.ID)
	require.Equal(t, item.Type, itemOut.Type)
	require.Equal(t, item.Secret().Data, itemOut.Secret().Data)
	require.Equal(t, []byte("keys.app"), item.SecretFor("website").Data)
	require.Equal(t, "keys.app", item.SecretFor("website").String())
	require.Equal(t, "", item.SecretFor("notfound").String())

	secretKey2 := randKey()
	_, err = DecodeItem(b, secretKey2)
	require.EqualError(t, err, "invalid keyring auth")

	itemOut3, err := DecodeItem(b, nil)
	require.NoError(t, err)
	require.Equal(t, item.ID, itemOut3.ID)
	require.Equal(t, item.Type, itemOut3.Type)
	require.Nil(t, itemOut3.Secret())
}
