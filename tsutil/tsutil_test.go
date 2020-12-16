package tsutil_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestParseMillis(t *testing.T) {
	t1 := time.Now().UTC()
	ts1 := tsutil.Millis(t1)
	t2 := tsutil.ConvertMillis(ts1)
	require.Equal(t, t1.Format(time.StampMilli), t2.Format(time.StampMilli))

	require.Equal(t, int64(0), tsutil.Millis(time.Time{}))
	require.Equal(t, time.Time{}, tsutil.ConvertMillis(0))

	t3 := tsutil.ConvertMillis(1234567890001)
	tf3 := t3.Format(http.TimeFormat)
	require.Equal(t, "Fri, 13 Feb 2009 23:31:30 GMT", tf3)
	tf3 = t3.Format(tsutil.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.001Z", tf3)

	t4 := tsutil.ParseMillis("1234567890001")
	tf4 := t4.Format(tsutil.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.001Z", tf4)
	require.Equal(t, int64(1234567890001), tsutil.Millis(t4))

	t5 := tsutil.ConvertMillis(1234567890001)
	tf5 := t5.Format(tsutil.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.001Z", tf5)
}

func TestRFC3339Milli(t *testing.T) {
	t1 := tsutil.ConvertMillis(1234567890010)
	s1 := t1.Format(tsutil.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.010Z", s1)
	tout, err := time.Parse(tsutil.RFC3339Milli, s1)
	require.NoError(t, err)
	require.Equal(t, tsutil.Millis(t1), tsutil.Millis(tout))
}

func TestDays(t *testing.T) {
	t1 := tsutil.ConvertMillis(1234567890001)
	days := tsutil.Days(t1)
	require.Equal(t, "14288", fmt.Sprintf("%d", days))
}
