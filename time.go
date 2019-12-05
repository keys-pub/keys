package keys

import (
	"time"
)

const (
	// RFC3339Milli is RFC3339 with millisecond precision
	RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"
)

// timeUntilNext returns how long until next duration.
// For example, for time.Hour, if time is 11:01, then time until next is 29m.
// For example, for time.Hour, if time is 11:49, then time until next is 41m.
// For example, for time.Minute*30, if time is 11:01, then time until next is 14m.
func timeUntilNext(ti time.Time, dt time.Duration) time.Duration {
	return nextTime(ti, dt).Add(dt / 2).Sub(ti)
}

// currentTime returns time truncated to half duration in the past.
// For example, for time.Hour, if time is 10:30:00-11:29:59, then previous time is 10.
// For example, for time.Hour, if time is 11:30:00-12:29:59, then previous time is 11.
func previousTime(ti time.Time, dt time.Duration) time.Time {
	return ti.Add(-dt / 2).Truncate(dt)
}

// nextTime returns time truncated to half duration in the future.
// For example, for time.Hour, if time is 10:30:00-11:29:59, then next time is 11.
// For example, for time.Hour, if time is 11:30:00-12:29:59, then next time is 12.
func nextTime(ti time.Time, dt time.Duration) time.Time {
	return ti.Add(dt / 2).Truncate(dt)
}

// formatWithPrecision formats string for time and precision in sortable format.
func formatWithPrecision(ti time.Time, precision time.Duration) string {
	ti = ti.Truncate(precision)
	if precision < time.Minute {
		return ti.Format("20060102150405")
	} else if precision < time.Hour {
		return ti.Format("200601021504")
	} else {
		return ti.Format("2006010215")
	}
}

// TimeMs is time as number of milliseconds from epoch.
type TimeMs int64

// TimeToMillis returns milliseconds since epoch from time.Time.
// If t.IsZero() we return 0.
func TimeToMillis(t time.Time) TimeMs {
	if t.IsZero() {
		return 0
	}
	return TimeMs(t.UnixNano() / int64(time.Millisecond))
}

// TimePtrToMillis returns milliseconds since epoch from time.Time.
// If t is nil or t.IsZero() we return 0.
func TimePtrToMillis(t *time.Time) TimeMs {
	if t == nil {
		return 0
	}
	return TimeToMillis(*t)
}

// TimeFromMillis returns time.Time from milliseconds since epoch.
func TimeFromMillis(m TimeMs) time.Time {
	if m == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(m)*int64(time.Millisecond))
}
