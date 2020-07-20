package tsutil

import "time"

// Clock returns time.Time.
type Clock interface {
	// Now returns current clock time.
	Now() time.Time

	// Add time to clock.
	Add(dt time.Duration)
}

// testClock increments a millisecond on each access.
// This is for testing.
type testClock struct {
	t    time.Time
	tick time.Duration
}

// NewTestClock returns a test Clock starting at 1234567890000 millseconds since
// epoch. Each access to Now() increases time by 1 millisecond.
func NewTestClock() Clock {
	t := ConvertMillis(1234567890000)
	return &testClock{
		t:    t,
		tick: time.Millisecond,
	}
}

// Now returns current clock time.
func (c *testClock) Now() time.Time {
	c.t = c.t.Add(c.tick)
	return c.t
}

// SetTick sets tick increment for clock.
func (c *testClock) SetTick(tick time.Duration) {
	c.tick = tick
}

// Add to clock.
func (c *testClock) Add(dt time.Duration) {
	c.t = c.t.Add(dt)
}

// NewTestClockAt creates a Clock starting at timestamp (millis).
func NewTestClockAt(ts int64) Clock {
	t := ConvertMillis(ts)
	return &testClock{
		t:    t,
		tick: time.Millisecond,
	}
}

// NewClock returns current clock time.
func NewClock() Clock {
	return &clock{
		add: time.Duration(0),
	}
}

type clock struct {
	add time.Duration
}

func (c *clock) Now() time.Time {
	return time.Now().Add(c.add)
}

func (c *clock) Add(dt time.Duration) {
	c.add = c.add + dt
}
