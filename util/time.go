package util

import (
	"time"
)

const (
	// RFC3339Milli is RFC3339 with millisecond precision
	RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"
)

// TimeToMillis returns milliseconds since epoch from time.Time.
// If t.IsZero() we return 0.
func TimeToMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return int64(t.UnixNano() / int64(time.Millisecond))
}

// TimePtrToMillis returns milliseconds since epoch from time.Time.
// If t is nil or t.IsZero() we return 0.
func TimePtrToMillis(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return TimeToMillis(*t)
}

// TimeFromMillis returns time.Time from milliseconds since epoch.
func TimeFromMillis(m int64) time.Time {
	if m == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(m)*int64(time.Millisecond)).UTC()
}
