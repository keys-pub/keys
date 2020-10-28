// Package tsutil provides timestamp and time utilities.
package tsutil

import (
	"strconv"
	"time"
)

const (
	// RFC3339Milli is RFC3339 with millisecond precision.
	RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"
)

// Millis returns milliseconds since epoch from time.Time.
// Returns 0 if t.IsZero().
func Millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return int64(t.UnixNano() / int64(time.Millisecond))
}

// MillisNow returns now in milliseconds since epoch.
func MillisNow() int64 {
	return Millis(time.Now())
}

// ParseMillis returns time.Time from milliseconds since epoch as string.
func ParseMillis(s string) time.Time {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return ConvertMillis(n)

}

// ConvertMillis returns time.Time from milliseconds since epoch.
func ConvertMillis(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n*int64(time.Millisecond)).UTC()
}
