package events_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/dstore/events"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestEvents(t *testing.T) {
	var err error

	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))
	eds := dstore.NewMem()
	clock := tsutil.NewTestClock()
	eds.SetClock(clock)

	ctx := context.TODO()
	path := dstore.Path("test", "eds")

	length := 40
	values := []events.Document{}
	strs := []string{}
	for i := 0; i < length; i++ {
		str := fmt.Sprintf("value%d", i)
		values = append(values, dstore.Data([]byte(str)))
		strs = append(strs, str)
	}
	idx, err := eds.EventsAdd(ctx, path, values)
	require.NoError(t, err)
	require.Equal(t, int64(40), idx)

	// Events (limit=10)
	iter, err := eds.Events(ctx, path, events.Limit(10))
	require.NoError(t, err)
	eventsValues := []string{}
	index := int64(0)
	for i := 0; ; i++ {
		event, err := iter.Next()
		require.NoError(t, err)
		if event == nil {
			break
		}
		require.NotEmpty(t, event.Timestamp)
		require.Equal(t, int64(i+1), event.Index)
		eventsValues = append(eventsValues, string(event.Data()))
		index = event.Index
	}
	iter.Release()
	require.Equal(t, 10, len(eventsValues))
	require.Equal(t, strs[0:10], eventsValues)

	// Events (index, limit=10)
	iter, err = eds.Events(ctx, path, events.Index(index), events.Limit(10))
	require.NoError(t, err)
	eventsValues = []string{}
	for i := 0; ; i++ {
		event, err := iter.Next()
		require.NoError(t, err)
		if event == nil {
			break
		}
		eventsValues = append(eventsValues, string(event.Data()))
		index = event.Index
	}
	iter.Release()
	require.Equal(t, int64(20), index)
	require.Equal(t, 10, len(eventsValues))

	require.Equal(t, strs[10:20], eventsValues)

	// Events (large index)
	large := int64(1000000000)
	iter, err = eds.Events(ctx, path, events.Index(large))
	require.NoError(t, err)
	event, err := iter.Next()
	require.NoError(t, err)
	require.Nil(t, event)
	iter.Release()

	// Descending
	revs := reverseCopy(strs)

	// Events (limit=10, desc)
	iter, err = eds.Events(ctx, path, events.Limit(10), events.WithDirection(events.Descending))
	require.NoError(t, err)
	eventsValues = []string{}
	for i := 0; ; i++ {
		event, err := iter.Next()
		require.NoError(t, err)
		if event == nil {
			break
		}
		eventsValues = append(eventsValues, string(event.Data()))
		index = event.Index
	}
	iter.Release()
	require.Equal(t, 10, len(eventsValues))
	require.Equal(t, int64(31), index)
	require.Equal(t, revs[0:10], eventsValues)

	// Events (limit=5, index, desc)
	iter, err = eds.Events(ctx, path, events.Index(index), events.Limit(5), events.WithDirection(events.Descending))
	require.NoError(t, err)
	eventsValues = []string{}
	for i := 0; ; i++ {
		event, err := iter.Next()
		require.NoError(t, err)
		if event == nil {
			break
		}
		eventsValues = append(eventsValues, string(event.Data()))
		index = event.Index
	}
	iter.Release()
	require.Equal(t, 5, len(eventsValues))
	require.Equal(t, int64(26), index)
	require.Equal(t, revs[10:15], eventsValues)

	positions, err := eds.EventPositions(ctx, []string{path})
	require.NoError(t, err)
	require.Equal(t, 1, len(positions))
	require.Equal(t, int64(40), positions[path].Index)

	// Delete
	ok, err := eds.EventsDelete(ctx, path)
	require.NoError(t, err)
	require.True(t, ok)

	iter, err = eds.Events(ctx, path)
	require.NoError(t, err)
	event, err = iter.Next()
	require.NoError(t, err)
	require.Nil(t, event)
	iter.Release()

	positions, err = eds.EventPositions(ctx, []string{path})
	require.NoError(t, err)
	require.Equal(t, 0, len(positions))

	ok, err = eds.EventsDelete(ctx, path)
	require.NoError(t, err)
	require.False(t, ok)
}

func reverseCopy(s []string) []string {
	a := make([]string, len(s))
	for i, j := 0, len(s)-1; i < len(s); i++ {
		a[i] = s[j]
		j--
	}
	return a
}

func TestIncrement(t *testing.T) {
	var err error

	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))
	eds := dstore.NewMem()
	clock := tsutil.NewTestClock()
	eds.SetClock(clock)

	n, i, err := eds.Increment(context.TODO(), "/test/doc1", "count", 1)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.Equal(t, int64(1), i)

	n, i, err = eds.Increment(context.TODO(), "/test/doc1", "count", 5)
	require.NoError(t, err)
	require.Equal(t, int64(6), n)
	require.Equal(t, int64(2), i)
}

func TestEventsConcurrent(t *testing.T) {
	eds := dstore.NewMem()
	ctx := context.TODO()
	path := "test/doc1"

	_, err := eds.EventAdd(ctx, path, dstore.Data([]byte("testing")))
	require.NoError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(4)

	fn := func(group string) {
		var ferr error
		for i := 1; i < 5; i++ {
			val := fmt.Sprintf("testing-%s-%d", group, i)
			_, ferr = eds.EventAdd(ctx, path, dstore.Data([]byte(val)))
			if ferr != nil {
				break
			}
		}
		wg.Done()
		require.NoError(t, ferr)
	}
	go fn("a")
	go fn("b")
	go fn("c")
	go fn("d")

	wg.Wait()

	idx := int64(1)
	iter, err := eds.Events(ctx, path)
	require.NoError(t, err)
	defer iter.Release()
	for {
		event, err := iter.Next()
		require.NoError(t, err)
		if event == nil {
			break
		}
		require.Equal(t, idx, event.Index)
		idx++
	}
}
