package keys_test

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestDocument(t *testing.T) {
	db := keys.NewMem()
	clock := newClock()
	db.SetTimeNow(clock.Now)
	ctx := context.TODO()

	paths := []string{}
	for i := 0; i < 4; i++ {
		p := keys.Path("test", strconv.Itoa(i))
		err := db.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
		paths = append(paths, p)
	}
	sort.Strings(paths)

	iter, err := db.Documents(ctx, "test", nil)
	require.NoError(t, err)
	docs, err := keys.DocumentsFromIterator(iter)
	require.NoError(t, err)
	require.Equal(t, 4, len(docs))
	require.Equal(t, "/test/0", docs[0].Path)
	require.Equal(t, []byte("value0"), docs[0].Data)
	require.Equal(t, keys.TimeMs(1234567890001), keys.TimeToMillis(docs[0].CreatedAt))

	pathsOut := keys.DocumentPaths(docs)
	require.Equal(t, paths, pathsOut)

	doc := keys.NewDocument("test/6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
	doc = keys.NewDocument("//test//6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
}
