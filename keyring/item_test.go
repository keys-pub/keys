package keyring_test

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestItem(t *testing.T) {
	clock := tsutil.NewClock()
	secretKey := randKey()
	item := keyring.NewItem("account1", []byte("password"), "passphrase", clock.Now())
	b, err := item.Marshal(secretKey)
	require.NoError(t, err)

	_, err = item.Marshal(nil)
	require.EqualError(t, err, "no secret key specified")

	itemOut, err := keyring.DecryptItem(b, secretKey)
	require.NoError(t, err)

	require.Equal(t, item.ID, itemOut.ID)
	require.Equal(t, item.Type, itemOut.Type)
	require.Equal(t, item.Data, itemOut.Data)

	secretKey2 := randKey()
	_, err = keyring.DecryptItem(b, secretKey2)
	require.EqualError(t, err, "invalid keyring auth")

	b, err = msgpack.Marshal(item)
	require.NoError(t, err)
	expected := `([]uint8) (len=56 cap=64) {
 00000000  84 a2 69 64 a8 61 63 63  6f 75 6e 74 31 a3 74 79  |..id.account1.ty|
 00000010  70 aa 70 61 73 73 70 68  72 61 73 65 a3 64 61 74  |p.passphrase.dat|
 00000020  c4 08 70 61 73 73 77 6f  72 64 a3 63 74 73 d7 ff  |..password.cts..|
 00000030  00 3d 09 00 49 96 02 d2                           |.=..I...|
}
`
	require.Equal(t, expected, spew.Sdump(b))
}
