package ds

import (
	"context"
	"time"
)

// Change is used to add versioned data to a collection.
// If this format changes, you should also change in firestore and other
// backends that don't directly use this struct on set.
type Change struct {
	Data      []byte    `json:"data" firestore:"data"`
	Version   int64     `json:"v" firestore:"v"`
	Timestamp time.Time `json:"ts" firestore:"ts"`
}

// Direction is ascending or descending.
type Direction string

const (
	// Ascending direction.
	Ascending Direction = "asc"
	// Descending direction.
	Descending Direction = "desc"
)

// Changes describes changes to a path.
type Changes interface {
	// ChangesAdd adds changes and returns paths.
	ChangesAdd(ctx context.Context, collection string, data [][]byte) error
	// Changes from version.
	Changes(ctx context.Context, collection string, version int64, limit int, direction Direction) (ChangeIterator, error)
}
