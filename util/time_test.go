package util_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/keys-pub/keys/util"
	"github.com/stretchr/testify/require"
)

func TestTimeInMillis(t *testing.T) {
	t1 := time.Now().UTC()
	ts := util.TimeToMillis(t1)
	t2 := util.TimeFromMillis(ts)
	require.Equal(t, t1.Format(time.StampMilli), t2.Format(time.StampMilli))

	require.Equal(t, int64(0), util.TimeToMillis(time.Time{}))
	require.Equal(t, time.Time{}, util.TimeFromMillis(0))

	t3 := util.TimeFromMillis(1234567890001)
	tf3 := t3.Format(http.TimeFormat)
	require.Equal(t, "Fri, 13 Feb 2009 23:31:30 GMT", tf3)
	tf3 = t3.Format(util.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.001Z", tf3)
}

func TestRFC3339Milli(t *testing.T) {
	t1 := util.TimeFromMillis(1234567890010)
	s1 := t1.Format(util.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.010Z", s1)
	tout, err := time.Parse(util.RFC3339Milli, s1)
	require.NoError(t, err)
	require.Equal(t, util.TimeToMillis(t1), util.TimeToMillis(tout))
}
