package events

// Iterator is an iterator for Event's.
type Iterator interface {
	// Next document, or nil.
	Next() (*Event, error)
	// Release resources associated with the iterator.
	Release()
}

// NewIterator returns an iterator for a Event slice.
func NewIterator(events []*Event) Iterator {
	return &iterator{events: events}
}

type iterator struct {
	events []*Event
	index  int
}

func (i *iterator) Next() (*Event, error) {
	if i.index >= len(i.events) {
		return nil, nil
	}
	d := i.events[i.index]
	i.index++
	return d, nil
}

func (i *iterator) Release() {
	i.events = nil
}
