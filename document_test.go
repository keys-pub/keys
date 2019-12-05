package keys

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocument(t *testing.T) {
	db := NewMem()
	clock := newClock()
	db.SetTimeNow(clock.Now)
	ctx := context.TODO()

	paths := []string{}
	for i := 0; i < 4; i++ {
		p := Path("test", strconv.Itoa(i))
		err := db.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
		paths = append(paths, p)
	}
	sort.Strings(paths)

	docs, err := db.list(ctx, "test", nil)
	require.NoError(t, err)
	require.Equal(t, 4, len(docs))
	require.Equal(t, "/test/0", docs[0].Path)
	require.Equal(t, []byte("value0"), docs[0].Data)
	require.Equal(t, TimeMs(1234567890001), TimeToMillis(docs[0].CreatedAt))

	pathsOut := documentPaths(docs)
	require.Equal(t, paths, pathsOut)

	doc := NewDocument("test/6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
	doc = NewDocument("//test//6", []byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
}
