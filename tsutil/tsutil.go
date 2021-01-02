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

// Millis returns milliseconds since epoch to t.
// Returns 0 if t.IsZero().
func Millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return int64(t.UnixNano() / int64(time.Millisecond))
}

// NowMillis returns now in milliseconds since epoch.
func NowMillis() int64 {
	return Millis(time.Now())
}

// ParseMillis returns time.Time from milliseconds since epoch.
func ParseMillis(i interface{}) time.Time {
	switch v := i.(type) {
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}
		}
		return millis(n)
	case int64:
		return millis(v)
	case int:
		return millis(int64(v))
	default:
		return time.Time{}
	}
}

// millis returns time.Time from milliseconds since epoch.
func millis(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n*int64(time.Millisecond)).UTC()
}

// Days returns days since epoch to t.
func Days(t time.Time) int {
	ms := Millis(t)
	return int(ms / 1000 / 60 / 60 / 24)
}
