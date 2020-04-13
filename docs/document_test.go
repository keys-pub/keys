package docs_test

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/stretchr/testify/require"
)

func TestDocument(t *testing.T) {
	db := docs.NewMem()
	clock := newClock()
	db.SetTimeNow(clock.Now)
	ctx := context.TODO()

	paths := []string{}
	for i := 0; i < 4; i++ {
		p := docs.Path("test", strconv.Itoa(i))
		err := db.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
		paths = append(paths, p)
	}
	sort.Strings(paths)

	iter, err := db.Documents(ctx, "test", nil)
	require.NoError(t, err)
	out, err := docs.DocumentsFromIterator(iter)
	require.NoError(t, err)
	require.Equal(t, 4, len(out))
	require.Equal(t, "/test/0", out[0].Path)
	require.Equal(t, []byte("value0"), out[0].Data)
	require.Equal(t, keys.TimeMs(1234567890001), keys.TimeToMillis(out[0].CreatedAt))

	pathsOut := docs.DocumentPaths(out)
	require.Equal(t, paths, pathsOut)

	doc := docs.NewDocument("test/6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
	doc = docs.NewDocument("//test//6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
}
