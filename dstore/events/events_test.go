package events_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/dstore/events"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
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
	values := [][]byte{}
	strs := []string{}
	for i := 0; i < length; i++ {
		str := fmt.Sprintf("value%d", i)
		values = append(values, []byte(str))
		strs = append(strs, str)
	}
	out, idx, err := eds.EventsAdd(ctx, path, values)
	require.NoError(t, err)
	require.Equal(t, 40, len(out))
	require.Equal(t, int64(40), idx)
	for i, event := range out {
		require.NotEmpty(t, event.Timestamp)
		require.Equal(t, int64(i+1), event.Index)
	}

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
		eventsValues = append(eventsValues, string(event.Data))
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
		eventsValues = append(eventsValues, string(event.Data))
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
		eventsValues = append(eventsValues, string(event.Data))
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
		eventsValues = append(eventsValues, string(event.Data))
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

func TestEventMarshal(t *testing.T) {
	clock := tsutil.NewTestClock()
	event := events.Event{
		Data:      []byte{0x01, 0x02, 0x03},
		Index:     123,
		Timestamp: tsutil.Millis(clock.Now()),
	}
	out, err := msgpack.Marshal(event)
	require.NoError(t, err)
	expected := `([]uint8) (len=35 cap=64) {
 00000000  83 a3 64 61 74 c4 03 01  02 03 a3 69 64 78 d3 00  |..dat......idx..|
 00000010  00 00 00 00 00 00 7b a2  74 73 d3 00 00 01 1f 71  |......{.ts.....q|
 00000020  fb 04 51                                          |..Q|
}
`
	require.Equal(t, expected, spew.Sdump(out))

	out, err = json.Marshal(event)
	require.NoError(t, err)
	expected = `([]uint8) (len=44 cap=48) {
 00000000  7b 22 64 61 74 61 22 3a  22 41 51 49 44 22 2c 22  |{"data":"AQID","|
 00000010  69 64 78 22 3a 31 32 33  2c 22 74 73 22 3a 31 32  |idx":123,"ts":12|
 00000020  33 34 35 36 37 38 39 30  30 30 31 7d              |34567890001}|
}
`
	require.Equal(t, expected, spew.Sdump(out))
}
