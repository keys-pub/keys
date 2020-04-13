package docs_test

import (
	"context"
	"sync"
	"testing"

	"github.com/keys-pub/keys/docs"
	"github.com/stretchr/testify/require"
)

func TestWatch(t *testing.T) {
	fi := docs.NewMem()
	ctx := context.TODO()

	root1 := docs.Path("testwatch1")
	root2 := docs.Path("testwatch2")

	start := sync.WaitGroup{}
	start.Add(2)

	wg := sync.WaitGroup{}
	wg.Add(2)
	ln1 := func(e *docs.WatchEvent) {
		switch e.Status {
		case docs.WatchStatusStarting:
			start.Done()
		case docs.WatchStatusData:
			fi.StopWatching(root1)
		}
	}

	ln2 := func(e *docs.WatchEvent) {
		switch e.Status {
		case docs.WatchStatusStarting:
			start.Done()
		case docs.WatchStatusData:
			fi.StopWatching(root2)
		}
	}

	go func() {
		watchErr := fi.Watch(root1, ln1)
		require.NoError(t, watchErr)
		wg.Done()
	}()

	go func() {
		watchErr := fi.Watch(root2, ln2)
		require.NoError(t, watchErr)
		wg.Done()
	}()

	start.Wait()

	err := fi.Create(ctx, docs.Path(root1, "val1"), []byte("testdata1"))
	require.NoError(t, err)

	err = fi.Create(ctx, docs.Path(root2, "val2"), []byte("testdata2"))
	require.NoError(t, err)

	wg.Wait()
}

func TestWatching(t *testing.T) {
	fi := docs.NewMem()

	start := sync.WaitGroup{}
	start.Add(2)
	stop := sync.WaitGroup{}
	stop.Add(2)
	ln := func(e *docs.WatchEvent) {
		switch e.Status {
		case docs.WatchStatusStarting:
			start.Done()
		case docs.WatchStatusStopping:
			stop.Done()
		}
	}

	go func() {
		watchErr := fi.Watch("/test1", ln)
		require.NoError(t, watchErr)
	}()
	go func() {
		watchErr2 := fi.Watch("/test2", ln)
		require.NoError(t, watchErr2)
	}()
	start.Wait()

	watchErr3 := fi.Watch("/test1", nil)
	require.EqualError(t, watchErr3, "already watching /test1")

	fi.StopWatching("/test1")
	fi.StopWatchingAll()
	stop.Wait()
}
