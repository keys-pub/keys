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

func TestX25519Marshal(t *testing.T) {
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewX25519KeyFromSeed(testSeed(0xef)))
	key.Notes = "some test notes"
	key.CreatedAt = clock.NowMillis()
	key.UpdatedAt = clock.NowMillis()

	b, err := msgpack.Marshal(key)
	require.NoError(t, err)
	expected := `([]uint8) (len=205 cap=395) {
 00000000  87 a2 69 64 d9 3e 6b 62  78 31 30 71 64 79 79 78  |..id.>kbx10qdyyx|
 00000010  6c 7a 6c 6d 68 32 74 65  68 78 33 65 6a 32 79 78  |lzlmh2tehx3ej2yx|
 00000020  77 64 34 77 7a 71 70 66  39 6e 6c 35 38 61 77 74  |wd4wzqpf9nl58awt|
 00000030  36 33 30 66 66 7a 34 75  61 66 79 65 74 71 68 73  |630ffz4uafyetqhs|
 00000040  63 37 33 66 a4 74 79 70  65 a6 78 32 35 35 31 39  |c73f.type.x25519|
 00000050  a4 70 72 69 76 c4 20 ef  ef ef ef ef ef ef ef ef  |.priv. .........|
 00000060  ef ef ef ef ef ef ef ef  ef ef ef ef ef ef ef ef  |................|
 00000070  ef ef ef ef ef ef ef a3  70 75 62 c4 20 78 1a 42  |........pub. x.B|
 00000080  1b e2 fe ee a5 e6 e6 8e  64 a2 19 cd ab 84 00 a4  |........d.......|
 00000090  b3 fd 0f d7 2f 51 7a 52  2a f3 a9 26 56 a3 63 74  |..../QzR*..&V.ct|
 000000a0  73 d3 00 00 01 1f 71 fb  04 51 a3 75 74 73 d3 00  |s.....q..Q.uts..|
 000000b0  00 01 1f 71 fb 04 52 a5  6e 6f 74 65 73 af 73 6f  |...q..R.notes.so|
 000000c0  6d 65 20 74 65 73 74 20  6e 6f 74 65 73           |me test notes|
}
`
	require.Equal(t, expected, spew.Sdump(b))

	b, err = json.MarshalIndent(key, "", "  ")
	require.NoError(t, err)
	expected = `{
  "id": "kbx10qdyyxlzlmh2tehx3ej2yxwd4wzqpf9nl58awt630ffz4uafyetqhsc73f",
  "type": "x25519",
  "priv": "7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+8=",
  "pub": "eBpCG+L+7qXm5o5kohnNq4QApLP9D9cvUXpSKvOpJlY=",
  "cts": 1234567890001,
  "uts": 1234567890002,
  "notes": "some test notes"
}`
	require.Equal(t, expected, string(b))
}

func TestX25519MarshalPublic(t *testing.T) {
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewX25519KeyFromSeed(testSeed(0xef)).PublicKey())
	key.Notes = "some test notes"
	key.CreatedAt = clock.NowMillis()
	key.UpdatedAt = clock.NowMillis()

	b, err := msgpack.Marshal(key)
	require.NoError(t, err)
	expected := `([]uint8) (len=166 cap=190) {
 00000000  86 a2 69 64 d9 3e 6b 62  78 31 30 71 64 79 79 78  |..id.>kbx10qdyyx|
 00000010  6c 7a 6c 6d 68 32 74 65  68 78 33 65 6a 32 79 78  |lzlmh2tehx3ej2yx|
 00000020  77 64 34 77 7a 71 70 66  39 6e 6c 35 38 61 77 74  |wd4wzqpf9nl58awt|
 00000030  36 33 30 66 66 7a 34 75  61 66 79 65 74 71 68 73  |630ffz4uafyetqhs|
 00000040  63 37 33 66 a4 74 79 70  65 a6 78 32 35 35 31 39  |c73f.type.x25519|
 00000050  a3 70 75 62 c4 20 78 1a  42 1b e2 fe ee a5 e6 e6  |.pub. x.B.......|
 00000060  8e 64 a2 19 cd ab 84 00  a4 b3 fd 0f d7 2f 51 7a  |.d.........../Qz|
 00000070  52 2a f3 a9 26 56 a3 63  74 73 d3 00 00 01 1f 71  |R*..&V.cts.....q|
 00000080  fb 04 51 a3 75 74 73 d3  00 00 01 1f 71 fb 04 52  |..Q.uts.....q..R|
 00000090  a5 6e 6f 74 65 73 af 73  6f 6d 65 20 74 65 73 74  |.notes.some test|
 000000a0  20 6e 6f 74 65 73                                 | notes|
}
`
	require.Equal(t, expected, spew.Sdump(b))

	b, err = json.MarshalIndent(key, "", "  ")
	require.NoError(t, err)
	expected = `{
  "id": "kbx10qdyyxlzlmh2tehx3ej2yxwd4wzqpf9nl58awt630ffz4uafyetqhsc73f",
  "type": "x25519",
  "pub": "eBpCG+L+7qXm5o5kohnNq4QApLP9D9cvUXpSKvOpJlY=",
  "cts": 1234567890001,
  "uts": 1234567890002,
  "notes": "some test notes"
}`
	require.Equal(t, expected, string(b))
}
