package ds

import "time"

// DocumentIterator is an iterator for Document's.
type DocumentIterator interface {
	// Next document, or nil.
	Next() (*Document, error)
	// Release resources associated with the iterator.
	Release()
}

// NewDocumentIterator returns an iterator for a Document slice.
func NewDocumentIterator(docs ...*Document) DocumentIterator {
	return &docsIterator{docs: docs}
}

type docsIterator struct {
	docs  []*Document
	index int
}

func (i *docsIterator) Next() (*Document, error) {
	if i.index >= len(i.docs) {
		return nil, nil
	}
	d := i.docs[i.index]
	i.index++
	return d, nil
}

func (i *docsIterator) Release() {
	i.docs = nil
}

// CollectionIterator is an iterator for Collection's.
type CollectionIterator interface {
	// Next collection, or nil.
	Next() (*Collection, error)
	// Release resources associated with the iterator.
	Release()
}

// NewCollectionIterator returns an iterator for a Collection slice.
func NewCollectionIterator(cols []*Collection) CollectionIterator {
	return &colsIterator{cols: cols}
}

type colsIterator struct {
	cols  []*Collection
	index int
}

func (i *colsIterator) Next() (*Collection, error) {
	if i.index >= len(i.cols) {
		return nil, nil
	}
	c := i.cols[i.index]
	i.index++
	return c, nil
}

func (i *colsIterator) Release() {
	i.cols = nil
}

// CollectionsFromIterator returns Collection's from CollectionIterator.
func CollectionsFromIterator(iter CollectionIterator) ([]*Collection, error) {
	cols := []*Collection{}
	for {
		col, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if col == nil {
			break
		}
		cols = append(cols, col)
	}
	return cols, nil
}

// DocumentsFromIterator returns Document's from DocumentIterator.
func DocumentsFromIterator(iter DocumentIterator) ([]*Document, error) {
	docs := []*Document{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

// ChangeIterator is an iterator for Change's.
type ChangeIterator interface {
	// Next document, or nil.
	Next() (*Change, error)
	// Release resources associated with the iterator.
	Release()
}

// NewChangeIterator returns an iterator for a Change slice.
func NewChangeIterator(changes []*Change) ChangeIterator {
	return &changesIterator{changes: changes}
}

type changesIterator struct {
	changes []*Change
	index   int
}

func (i *changesIterator) Next() (*Change, error) {
	if i.index >= len(i.changes) {
		return nil, nil
	}
	d := i.changes[i.index]
	i.index++
	return d, nil
}

func (i *changesIterator) Release() {
	i.changes = nil
}

// ChangesFromIterator returns Change's from ChangeIterator.
func ChangesFromIterator(iter ChangeIterator, from time.Time) ([]*Change, time.Time, error) {
	changes := []*Change{}
	for {
		change, err := iter.Next()
		if err != nil {
			return nil, time.Time{}, err
		}
		if change == nil {
			break
		}
		changes = append(changes, change)
	}
	to := from
	if len(changes) > 0 {
		to = changes[len(changes)-1].Timestamp
	}
	return changes, to, nil
}
