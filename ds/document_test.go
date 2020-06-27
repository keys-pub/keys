package ds_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys/ds"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestDocument(t *testing.T) {
	db := ds.NewMem()
	clock := tsutil.NewClock()
	db.SetTimeNow(clock.Now)
	ctx := context.TODO()

	paths := []string{}
	for i := 0; i < 4; i++ {
		p := ds.Path("test", strconv.Itoa(i))
		err := db.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
		paths = append(paths, p)
	}
	sort.Strings(paths)

	iter, err := db.DocumentIterator(ctx, "test")
	require.NoError(t, err)
	out1, err := iter.Next()
	require.NoError(t, err)
	require.Equal(t, "/test/0", out1.Path)
	require.Equal(t, []byte("value0"), out1.Data)
	require.Equal(t, int64(1234567890001), tsutil.Millis(out1.CreatedAt))

	out2, err := iter.Next()
	require.NoError(t, err)
	out3, err := iter.Next()
	require.NoError(t, err)
	out4, err := iter.Next()
	require.NoError(t, err)

	require.Equal(t, paths, []string{out1.Path, out2.Path, out3.Path, out4.Path})

	doc := ds.NewDocument("test/6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
	doc = ds.NewDocument("//test//6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
}

func TestDocumentMarshal(t *testing.T) {
	clock := tsutil.NewClock()
	doc := ds.NewDocument("/test/key1", []byte("value"))
	doc.CreatedAt = clock.Now()
	doc.UpdatedAt = clock.Now()
	out, err := msgpack.Marshal(doc)
	require.NoError(t, err)
	expected := `([]uint8) (len=53 cap=64) {
 00000000  84 a1 70 aa 2f 74 65 73  74 2f 6b 65 79 31 a3 64  |..p./test/key1.d|
 00000010  61 74 c4 05 76 61 6c 75  65 a3 63 74 73 d7 ff 00  |at..value.cts...|
 00000020  3d 09 00 49 96 02 d2 a3  75 74 73 d7 ff 00 7a 12  |=..I....uts...z.|
 00000030  00 49 96 02 d2                                    |.I...|
}
`
	require.Equal(t, expected, spew.Sdump(out))

	out, err = json.Marshal(doc)
	require.NoError(t, err)
	expected = `([]uint8) (len=105 cap=112) {
 00000000  7b 22 70 61 74 68 22 3a  22 2f 74 65 73 74 2f 6b  |{"path":"/test/k|
 00000010  65 79 31 22 2c 22 64 61  74 61 22 3a 22 64 6d 46  |ey1","data":"dmF|
 00000020  73 64 57 55 3d 22 2c 22  63 74 73 22 3a 22 32 30  |sdWU=","cts":"20|
 00000030  30 39 2d 30 32 2d 31 33  54 32 33 3a 33 31 3a 33  |09-02-13T23:31:3|
 00000040  30 2e 30 30 31 5a 22 2c  22 75 74 73 22 3a 22 32  |0.001Z","uts":"2|
 00000050  30 30 39 2d 30 32 2d 31  33 54 32 33 3a 33 31 3a  |009-02-13T23:31:|
 00000060  33 30 2e 30 30 32 5a 22  7d                       |30.002Z"}|
}
`
	require.Equal(t, expected, spew.Sdump(out))
}
