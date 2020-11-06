package docs_test

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"testing"

	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestDocument(t *testing.T) {
	mem := docs.NewMem()
	clock := tsutil.NewTestClock()
	mem.SetClock(clock)
	ctx := context.TODO()

	paths := []string{}
	for i := 0; i < 4; i++ {
		p := docs.Path("test", strconv.Itoa(i))
		err := mem.Create(ctx, p, docs.NewFields("data", []byte(fmt.Sprintf("value%d", i))))
		require.NoError(t, err)
		paths = append(paths, p)
	}
	sort.Strings(paths)

	iter, err := mem.DocumentIterator(ctx, "test")
	require.NoError(t, err)
	out1, err := iter.Next()
	require.NoError(t, err)
	require.Equal(t, "/test/0", out1.Path)
	require.Equal(t, []byte("value0"), out1.Bytes("data"))
	require.Equal(t, int64(1234567890001), tsutil.Millis(out1.CreatedAt))

	out2, err := iter.Next()
	require.NoError(t, err)
	out3, err := iter.Next()
	require.NoError(t, err)
	out4, err := iter.Next()
	require.NoError(t, err)

	require.Equal(t, paths, []string{out1.Path, out2.Path, out3.Path, out4.Path})

	doc := docs.NewDocument("test/6").WithData([]byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
	doc = docs.NewDocument("//test//6").WithData([]byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
}
