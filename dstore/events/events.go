// Package events provides an event log.
package events

import (
	"context"
)

// Event in an event log.
// If this format changes, you should also change in firestore and other
// backends that don't directly use this struct on set.
type Event struct {
	Document map[string]interface{} `json:"doc" msgpack:"doc" firestore:"doc"`

	// Index for event (read only).
	Index int64 `json:"idx" msgpack:"idx" firestore:"idx"`
	// Timestamp (read only). The time at which the event was created.
	// Firestore sets this to the document create time.
	Timestamp int64 `json:"ts" msgpack:"ts" firestore:"-"`
}

func (e Event) Data() []byte {
	b, ok := e.Document["data"].([]byte)
	if !ok {
		return nil
	}
	return b
}

// Position describes a position in an event log.
type Position struct {
	Path      string `json:"path" msgpack:"path"`
	Index     int64  `json:"idx" msgpack:"idx"`
	Timestamp int64  `json:"ts" msgpack:"ts"`
}

type Document map[string]interface{}

// Events describes an append only event log.
type Events interface {
	// EventAdd adds (appends) event to the log.
	EventAdd(ctx context.Context, path string, d Document) (int64, error)

	// EventsAdd adds (appends) events (in a batch if multiple) to the log.
	EventsAdd(ctx context.Context, path string, d []Document) (int64, error)

	// Events retrives events from log with the specified options.
	Events(ctx context.Context, path string, opt ...Option) (Iterator, error)

	// EventsDelete deletes all events at the specified path.
	EventsDelete(ctx context.Context, path string) (bool, error)

	// EventPosition returns current position of event logs at the specified path.
	EventPosition(ctx context.Context, path string) (*Position, error)

	// EventPositions returns current positions of event logs at the specified paths.
	EventPositions(ctx context.Context, paths []string) (map[string]*Position, error)

	// Increment document name at path n amount.
	// Returns the new value and the start of the index.
	Increment(ctx context.Context, path string, name string, n int64) (int64, int64, error)
}

// Direction is ascending or descending.
type Direction string

const (
	// Ascending direction.
	Ascending Direction = "asc"
	// Descending direction.
	Descending Direction = "desc"
)

// Options ...
type Options struct {
	// Index to start at.
	Index int64
	// Limit is number of documents (max) to return.
	Limit int64
	// Direction to list.
	Direction Direction
}

// Option ...
type Option func(*Options)

// Index option.
func Index(i int64) Option {
	return func(o *Options) { o.Index = i }
}

// Limit option.
func Limit(l int64) Option {
	return func(o *Options) { o.Limit = l }
}

// WithDirection option.
func WithDirection(d Direction) Option {
	return func(o *Options) { o.Direction = d }
}

// NewOptions parses Options.
func NewOptions(opts ...Option) Options {
	options := Options{
		Direction: Ascending,
	}
	for _, o := range opts {
		o(&options)
	}
	return options
}
