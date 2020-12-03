package api_test

import (
	"encoding/json"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestEdX25519Marshal(t *testing.T) {
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0xef)))
	key.Notes = "some test notes"
	key.CreatedAt = clock.NowMillis()
	key.UpdatedAt = clock.NowMillis()

	b, err := msgpack.Marshal(key)
	require.NoError(t, err)
	expected := `([]uint8) (len=239 cap=412) {
 00000000  87 a2 69 64 d9 3e 6b 65  78 31 66 7a 6c 72 64 66  |..id.>kex1fzlrdf|
 00000010  79 34 77 6c 79 61 74 75  72 63 71 6b 66 71 39 32  |y4wlyaturcqkfq92|
 00000020  79 77 6a 37 6c 66 74 39  61 77 74 64 67 37 30 64  |ywj7lft9awtdg70d|
 00000030  32 79 66 74 7a 68 73 70  6d 63 34 35 71 73 76 67  |2yftzhspmc45qsvg|
 00000040  68 68 65 70 a4 74 79 70  65 a8 65 64 78 32 35 35  |hhep.type.edx255|
 00000050  31 39 a4 70 72 69 76 c4  40 ef ef ef ef ef ef ef  |19.priv.@.......|
 00000060  ef ef ef ef ef ef ef ef  ef ef ef ef ef ef ef ef  |................|
 00000070  ef ef ef ef ef ef ef ef  ef 48 be 36 a4 95 77 c9  |.........H.6..w.|
 00000080  d5 f0 78 05 92 02 a8 8e  97 be 95 97 ae 5b 51 e7  |..x..........[Q.|
 00000090  b5 44 4a c5 78 07 78 ad  01 a3 70 75 62 c4 20 48  |.DJ.x.x...pub. H|
 000000a0  be 36 a4 95 77 c9 d5 f0  78 05 92 02 a8 8e 97 be  |.6..w...x.......|
 000000b0  95 97 ae 5b 51 e7 b5 44  4a c5 78 07 78 ad 01 a5  |...[Q..DJ.x.x...|
 000000c0  6e 6f 74 65 73 af 73 6f  6d 65 20 74 65 73 74 20  |notes.some test |
 000000d0  6e 6f 74 65 73 a3 63 74  73 d3 00 00 01 1f 71 fb  |notes.cts.....q.|
 000000e0  04 51 a3 75 74 73 d3 00  00 01 1f 71 fb 04 52     |.Q.uts.....q..R|
}
`
	require.Equal(t, expected, spew.Sdump(b))

	b, err = json.MarshalIndent(key, "", "  ")
	require.NoError(t, err)
	expected = `{
  "id": "kex1fzlrdfy4wlyaturcqkfq92ywj7lft9awtdg70d2yftzhspmc45qsvghhep",
  "type": "edx25519",
  "priv": "7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+9IvjaklXfJ1fB4BZICqI6XvpWXrltR57VESsV4B3itAQ==",
  "pub": "SL42pJV3ydXweAWSAqiOl76Vl65bUee1RErFeAd4rQE=",
  "notes": "some test notes",
  "cts": 1234567890001,
  "uts": 1234567890002
}`
	require.Equal(t, expected, string(b))
}

func TestEdX25519MarshalPublic(t *testing.T) {
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0xef)).PublicKey())
	key.Notes = "some test notes"
	key.CreatedAt = clock.NowMillis()
	key.UpdatedAt = clock.NowMillis()

	b, err := msgpack.Marshal(key)
	require.NoError(t, err)
	expected := `([]uint8) (len=168 cap=190) {
 00000000  86 a2 69 64 d9 3e 6b 65  78 31 66 7a 6c 72 64 66  |..id.>kex1fzlrdf|
 00000010  79 34 77 6c 79 61 74 75  72 63 71 6b 66 71 39 32  |y4wlyaturcqkfq92|
 00000020  79 77 6a 37 6c 66 74 39  61 77 74 64 67 37 30 64  |ywj7lft9awtdg70d|
 00000030  32 79 66 74 7a 68 73 70  6d 63 34 35 71 73 76 67  |2yftzhspmc45qsvg|
 00000040  68 68 65 70 a4 74 79 70  65 a8 65 64 78 32 35 35  |hhep.type.edx255|
 00000050  31 39 a3 70 75 62 c4 20  48 be 36 a4 95 77 c9 d5  |19.pub. H.6..w..|
 00000060  f0 78 05 92 02 a8 8e 97  be 95 97 ae 5b 51 e7 b5  |.x..........[Q..|
 00000070  44 4a c5 78 07 78 ad 01  a5 6e 6f 74 65 73 af 73  |DJ.x.x...notes.s|
 00000080  6f 6d 65 20 74 65 73 74  20 6e 6f 74 65 73 a3 63  |ome test notes.c|
 00000090  74 73 d3 00 00 01 1f 71  fb 04 51 a3 75 74 73 d3  |ts.....q..Q.uts.|
 000000a0  00 00 01 1f 71 fb 04 52                           |....q..R|
}
`
	require.Equal(t, expected, spew.Sdump(b))

	b, err = json.MarshalIndent(key, "", "  ")
	require.NoError(t, err)
	expected = `{
  "id": "kex1fzlrdfy4wlyaturcqkfq92ywj7lft9awtdg70d2yftzhspmc45qsvghhep",
  "type": "edx25519",
  "pub": "SL42pJV3ydXweAWSAqiOl76Vl65bUee1RErFeAd4rQE=",
  "notes": "some test notes",
  "cts": 1234567890001,
  "uts": 1234567890002
}`
	require.Equal(t, expected, string(b))
}
