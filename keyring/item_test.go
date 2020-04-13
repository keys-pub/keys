package keyring_test

import (
	"testing"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestItem(t *testing.T) {
	secretKey := randKey()
	item := keyring.NewItem("account1", []byte("password"), "passphrase", time.Now())
	b, err := item.Marshal(secretKey)
	require.NoError(t, err)

	_, err = item.Marshal(nil)
	require.EqualError(t, err, "no secret key specified")

	itemOut, err := keyring.DecodeItem(b, secretKey)
	require.NoError(t, err)

	require.Equal(t, item.ID, itemOut.ID)
	require.Equal(t, item.Type, itemOut.Type)
	require.Equal(t, item.Data, itemOut.Data)

	secretKey2 := randKey()
	_, err = keyring.DecodeItem(b, secretKey2)
	require.EqualError(t, err, "invalid keyring auth")
}
