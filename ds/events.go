package ds

import (
	"context"
	"time"
)

// Event in an event log.
// If this format changes, you should also change in firestore and other
// backends that don't directly use this struct on set.
type Event struct {
	// Data for event.
	Data []byte `json:"data" msgpack:"dat" firestore:"data"`

	// Index for event (read only).
	Index int64 `json:"idx" msgpack:"idx" firestore:"idx"`
	// Timestamp (read only). The time at which the event was created.
	// Firestore sets this to the document create time.
	Timestamp time.Time `json:"ts" msgpack:"ts" firestore:"-"`
}

// Direction is ascending or descending.
type Direction string

const (
	// Ascending direction.
	Ascending Direction = "asc"
	// Descending direction.
	Descending Direction = "desc"
)

// Events describes an append only event log.
type Events interface {
	// EventsAdd appends an event.
	EventsAdd(ctx context.Context, path string, data [][]byte) ([]*Event, error)
	// Events from index.
	Events(ctx context.Context, path string, index int64, limit int, direction Direction) (EventIterator, error)
}
