package api_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestEncode(t *testing.T) {
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.GenerateEdX25519Key()).
		Created(clock.NowMillis()).
		WithLabel("test")

	encoded, err := api.EncodeKey(key, "")
	require.NoError(t, err)

	out, err := api.DecodeKey(encoded, "")
	require.NoError(t, err)
	require.Equal(t, key, out)

	encoded, err = api.EncodeKey(key, "testpassword")
	require.NoError(t, err)

	out, err = api.DecodeKey(encoded, "testpassword")
	require.NoError(t, err)
	require.Equal(t, key, out)

	_, err = api.DecodeKey(encoded, "invalidpassword")
	require.EqualError(t, err, "failed to decode key")

	_, err = api.DecodeKey("invaliddata", "")
	require.EqualError(t, err, "failed to decode key")

	// Empty
	var empty struct{}
	_, err = api.DecodeKey(encodeStruct(empty, ""), "")
	require.EqualError(t, err, "invalid key")

	// Invalid msgpack
	_, err = api.DecodeKey(encodeBytes([]byte("????"), ""), "")
	require.EqualError(t, err, "invalid key")
}

func encodeStruct(i interface{}, password string) string {
	b, err := msgpack.Marshal(i)
	if err != nil {
		panic(err)
	}
	return encodeBytes(b, password)
}

func encodeBytes(b []byte, password string) string {
	return encoding.EncodeSaltpack(keys.EncryptWithPassword(b, password), "")
}

func TestDecodeOld(t *testing.T) {
	msg := `BEGIN EDX25519 KEY MESSAGE.
	AY6gPAVx9JSUsLg 3K8CNqUyNY87qiL FNNp7UBsIcvObJK mRtDzpcwQU1XpYa
	64FF0g4O0sDrhV4 qlp52vdQ5PG77D8 046ZdckukUl6reZ inOEqkDuOg5hynz
	k95BEExR31Sqenh rdqT3ADIdPu8f4f aXQaFejAp3Cb.
	END EDX25519 KEY MESSAGE.`
	out, err := api.DecodeKey(msg, "testpassword")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex10x6fdaazp2zy85m6cj7w57y4u0cc99xa3nmwjdldk9l4ajm3yadq70g0js"), out.ID)
}
