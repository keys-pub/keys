// Package tsutil provides timestamp and time utilities.
package tsutil

import (
	"time"
)

const (
	// RFC3339Milli is RFC3339 with millisecond precision.
	RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"
)

// Millis returns milliseconds since epoch from time.Time.
// If t.IsZero() we return 0.
func Millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return int64(t.UnixNano() / int64(time.Millisecond))
}

// ParseMillis returns time.Time from milliseconds since epoch.
func ParseMillis(m int64) time.Time {
	if m == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(m)*int64(time.Millisecond)).UTC()
}
