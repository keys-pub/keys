package tsutil

import "time"

// Clock for time increments on each access.
type Clock struct {
	t    time.Time
	tick time.Duration
}

// NewClock creates a Clock.
func NewClock() *Clock {
	t := ParseMillis(1234567890000)
	return &Clock{
		t:    t,
		tick: time.Millisecond,
	}
}

// Now returns current clock time.
func (c *Clock) Now() time.Time {
	c.t = c.t.Add(c.tick)
	return c.t
}

// SetTick sets tick increment for clock.
func (c *Clock) SetTick(tick time.Duration) {
	c.tick = tick
}

// Add to clock.
func (c *Clock) Add(dt time.Duration) {
	c.t = c.t.Add(dt)
}

// NewClockAt creates a Clock starting at timestamp (millis).
func NewClockAt(ts int64) *Clock {
	t := ParseMillis(ts)
	return &Clock{
		t:    t,
		tick: time.Millisecond,
	}
}
