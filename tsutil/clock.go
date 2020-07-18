package tsutil

import "time"

// clock increments a millisecond on each access.
// This is for testing.
type clock struct {
	t    time.Time
	tick time.Duration
}

// Clock returns time.Time.
type Clock interface {
	// Now returns current clock time.
	Now() time.Time

	// Add time to clock.
	Add(dt time.Duration)
}

// NewTestClock returns a test Clock starting at 1234567890000 millseconds since
// epoch. Each access to Now() increases time by 1 millisecond.
func NewTestClock() Clock {
	t := ConvertMillis(int64(1234567890000))
	return &clock{
		t:    t,
		tick: time.Millisecond,
	}
}

// Now returns current clock time.
func (c *clock) Now() time.Time {
	c.t = c.t.Add(c.tick)
	return c.t
}

// SetTick sets tick increment for clock.
func (c *clock) SetTick(tick time.Duration) {
	c.tick = tick
}

// Add to clock.
func (c *clock) Add(dt time.Duration) {
	c.t = c.t.Add(dt)
}

// NewTestClockAt creates a Clock starting at timestamp (millis).
func NewTestClockAt(ts int64) Clock {
	t := ConvertMillis(ts)
	return &clock{
		t:    t,
		tick: time.Millisecond,
	}
}
