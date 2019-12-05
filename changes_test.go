package keys

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testChanges(t *testing.T, ds DocumentStore, changes Changes) {
	ctx := context.TODO()

	for i := 0; i < 4; i++ {
		p := Path("test", fmt.Sprintf("%d", i))
		err := ds.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
		err = changes.ChangeAdd(ctx, "testchanges", p)
		require.NoError(t, err)
		change, err := changes.Change(ctx, "testchanges", p)
		require.NoError(t, err)
		require.Equal(t, p, change.Path)
		require.True(t, TimeToMillis(change.Timestamp) > 1234567890000)
	}

	iter, err := ds.Documents(ctx, "test", nil)
	require.NoError(t, err)
	iter.Release()

	iter, err = ds.Documents(ctx, "test", &DocumentsOpts{Index: 1, Limit: 2})
	require.NoError(t, err)
	doc, err := iter.Next()
	require.NoError(t, err)
	require.Equal(t, "/test/1", doc.Path)
	iter.Release()

	recent, ts, err := changes.Changes(ctx, "testchanges", time.Time{}, 0)
	require.NoError(t, err)
	require.Equal(t, 4, len(recent))
	recentPaths := []string{}
	for _, doc := range recent {
		recentPaths = append(recentPaths, doc.Path)
	}
	require.Equal(t, []string{"/test/0", "/test/1", "/test/2", "/test/3"}, recentPaths)

	recent2, _, err := changes.Changes(ctx, "testchanges", time.Time{}, 2)
	require.NoError(t, err)
	require.Equal(t, 2, len(recent2))
	recentPaths2 := []string{}
	for _, doc := range recent2 {
		recentPaths2 = append(recentPaths2, doc.Path)
	}
	require.Equal(t, []string{"/test/0", "/test/1"}, recentPaths2)

	entries3, err := ds.GetAll(ctx, recentPaths)
	require.NoError(t, err)
	require.Equal(t, len(recent), len(entries3))

	for i := 4; i < 6; i++ {
		p := Path("test", fmt.Sprintf("%d", i))
		err := ds.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
		err = changes.ChangeAdd(ctx, "testchanges", p)
		require.NoError(t, err)
	}

	recent3, ts3, err := changes.Changes(ctx, "testchanges", ts, 0)
	require.NoError(t, err)
	require.False(t, ts3.IsZero())
	require.Equal(t, 3, len(recent3))
	recentPaths3 := []string{}
	for _, doc := range recent3 {
		recentPaths3 = append(recentPaths3, doc.Path)
	}
	require.Equal(t, []string{"/test/3", "/test/4", "/test/5"}, recentPaths3)
}
