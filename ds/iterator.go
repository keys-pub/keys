package ds

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
