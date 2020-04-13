package ds_test

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/ds"
	"github.com/stretchr/testify/require"
)

func TestDocument(t *testing.T) {
	db := ds.NewMem()
	clock := newClock()
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

	iter, err := db.Documents(ctx, "test", nil)
	require.NoError(t, err)
	out, err := ds.DocumentsFromIterator(iter)
	require.NoError(t, err)
	require.Equal(t, 4, len(out))
	require.Equal(t, "/test/0", out[0].Path)
	require.Equal(t, []byte("value0"), out[0].Data)
	require.Equal(t, keys.TimeMs(1234567890001), keys.TimeToMillis(out[0].CreatedAt))

	pathsOut := ds.DocumentPaths(out)
	require.Equal(t, paths, pathsOut)

	doc := ds.NewDocument("test/6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
	doc = ds.NewDocument("//test//6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
}
