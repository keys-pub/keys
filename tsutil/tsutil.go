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
// If t.IsZero() we return 0.
func Millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return int64(t.UnixNano() / int64(time.Millisecond))
}

// ParseMillis returns time.Time from milliseconds since epoch.
func ParseMillis(i interface{}) time.Time {
	switch v := i.(type) {
	case int64:
		return parseInt64(v)
	case int:
		return parseInt64(int64(v))
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return time.Time{}
		}
		return parseInt64(int64(n))
	default:
		return time.Time{}
	}
}

func parseInt64(m int64) time.Time {
	if m == 0 {
		return time.Time{}
	}
	return time.Unix(0, m*int64(time.Millisecond)).UTC()
}
