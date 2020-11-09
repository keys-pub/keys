package http_test

import (
	"context"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestNonces(t *testing.T) {
	nonces := http.NewMem(tsutil.NewTestClock())

	n1 := encoding.MustEncode(keys.RandBytes(32), encoding.Base62)
	val, err := nonces.Get(context.TODO(), n1)
	require.NoError(t, err)
	require.Empty(t, val)

	err = nonces.Set(context.TODO(), n1, "1")
	require.NoError(t, err)

	val, err = nonces.Get(context.TODO(), n1)
	require.NoError(t, err)
	require.Equal(t, "1", val)
}

func TestNoncesExpiration(t *testing.T) {
	nonces := http.NewMem(tsutil.NewTestClock())

	n1 := encoding.MustEncode(keys.RandBytes(32), encoding.Base62)
	val, err := nonces.Get(context.TODO(), n1)
	require.NoError(t, err)
	require.Empty(t, val)

	err = nonces.Set(context.TODO(), n1, "1")
	require.NoError(t, err)
	err = nonces.Expire(context.TODO(), n1, time.Millisecond)
	require.NoError(t, err)

	val2, err := nonces.Get(context.TODO(), n1)
	require.NoError(t, err)
	require.Empty(t, val2)

	n2 := encoding.MustEncode(keys.RandBytes(32), encoding.Base62)
	err = nonces.Set(context.TODO(), n2, "2")
	require.NoError(t, err)
	err = nonces.Expire(context.TODO(), n2, time.Minute)
	require.NoError(t, err)

	val3, err := nonces.Get(context.TODO(), n2)
	require.NoError(t, err)
	require.Equal(t, "2", val3)
}

// func TestNoncesIncrement(t *testing.T) {
// 	var err error
//  nonces := http.NewMem(tsutil.NewTestClock())

// 	n1 := encoding.MustEncode(keys.RandBytes(32), encoding.Base62)

// 	err = nonces.Set(context.TODO(), n1, "1")
// 	require.NoError(t, err)

// 	val, err := nonces.Get(context.TODO(), n1)
// 	require.NoError(t, err)
// 	require.Equal(t, "1", val)

// 	n, err := nonces.Increment(context.TODO(), n1)
// 	require.NoError(t, err)
// 	require.Equal(t, int64(2), n)

// 	val, err = nonces.Get(context.TODO(), n1)
// 	require.NoError(t, err)
// 	require.Equal(t, "2", val)
// }
