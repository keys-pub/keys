package tsutil

import "time"

// Clock for time increments on each access.
type Clock struct {
	t time.Time
}

// NewClock creates a Clock.
func NewClock() *Clock {
	t := ParseMillis(1234567890000)
	return &Clock{
		t: t,
	}
}

// Now returns current clock time.
func (c *Clock) Now() time.Time {
	c.t = c.t.Add(time.Millisecond)
	return c.t
}
