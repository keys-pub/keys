package ds_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keys-pub/keys/ds"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestMemChanges(t *testing.T) {
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))
	changes := ds.NewMem()
	clock := tsutil.NewClock()
	changes.SetTimeNow(clock.Now)
	vclock := tsutil.NewClock()
	changes.SetIncrementFn(func(ctx context.Context) (int64, error) {
		return tsutil.Millis(vclock.Now()), nil
	})

	ctx := context.TODO()
	col := "changes"

	length := 40
	values := [][]byte{}
	strs := []string{}
	for i := 0; i < length; i++ {
		str := fmt.Sprintf("value%d", i)
		values = append(values, []byte(str))
		strs = append(strs, str)
	}
	_, err := changes.ChangeAdd(ctx, col, values)
	require.NoError(t, err)

	// Changes (limit=10, asc)
	iter, err := changes.Changes(ctx, col, 0, 10, ds.Ascending)
	require.NoError(t, err)
	chgs, version, err := ds.ChangesFromIterator(iter, 0)
	require.NoError(t, err)
	iter.Release()
	require.Equal(t, 10, len(chgs))
	chgsValues := []string{}
	for _, doc := range chgs {
		chgsValues = append(chgsValues, string(doc.Data))
	}
	require.Equal(t, strs[0:10], chgsValues)

	// Changes (version, asc)
	iter, err = changes.Changes(ctx, col, version, 10, ds.Ascending)
	require.NoError(t, err)
	chgs, version, err = ds.ChangesFromIterator(iter, version)
	require.NoError(t, err)
	iter.Release()
	require.Equal(t, int64(1234567890020), version)
	require.Equal(t, 10, len(chgs))
	chgsValues = []string{}
	for _, chg := range chgs {
		chgsValues = append(chgsValues, string(chg.Data))
	}
	require.Equal(t, strs[10:20], chgsValues)

	// Changes (max version)
	max := tsutil.Millis(time.Now())
	iter, err = changes.Changes(ctx, col, max, 100, ds.Ascending)
	require.NoError(t, err)
	chgs, version, err = ds.ChangesFromIterator(iter, max)
	require.NoError(t, err)
	iter.Release()
	require.Equal(t, 0, len(chgs))
	require.Equal(t, max, version)

	// Descending
	revs := reverseCopy(strs)

	// Changes (limit=10, desc)
	iter, err = changes.Changes(ctx, col, 0, 10, ds.Descending)
	require.NoError(t, err)
	chgs, version, err = ds.ChangesFromIterator(iter, 0)
	require.NoError(t, err)
	iter.Release()
	require.Equal(t, 10, len(chgs))
	require.Equal(t, int64(1234567890031), version)
	chgsValues = []string{}
	for _, chg := range chgs {
		chgsValues = append(chgsValues, string(chg.Data))
	}
	require.Equal(t, revs[0:10], chgsValues)

	// Changes (limit=5, version, desc)
	iter, err = changes.Changes(ctx, col, version, 5, ds.Descending)
	require.NoError(t, err)
	chgs, version, err = ds.ChangesFromIterator(iter, version)
	require.NoError(t, err)
	iter.Release()
	require.Equal(t, 5, len(chgs))
	require.Equal(t, int64(1234567890026), version)
	chgsValues = []string{}
	for _, chg := range chgs {
		chgsValues = append(chgsValues, string(chg.Data))
	}
	require.Equal(t, revs[10:15], chgsValues)
}

func reverseCopy(s []string) []string {
	a := make([]string, len(s))
	for i, j := 0, len(s)-1; i < len(s); i++ {
		a[i] = s[j]
		j--
	}
	return a
}
