package ds

// DocumentsOptions ...
type DocumentsOptions struct {
	// Prefix to filter on.
	Prefix string
	// Index is offset into number of documents.
	Index int
	// Limit is number of documents (max) to return.
	Limit int
	// NoData to only include only path in Document (no data).
	NoData bool
}

// DocumentsOption ...
type DocumentsOption func(*DocumentsOptions)

// NewDocumentsOptions parses DocumentsOptions.
func NewDocumentsOptions(opts ...DocumentsOption) DocumentsOptions {
	var options DocumentsOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// Prefix to list.
func Prefix(prefix string) DocumentsOption {
	return func(o *DocumentsOptions) {
		o.Prefix = prefix
	}
}

// Index to start at.
func Index(index int) DocumentsOption {
	return func(o *DocumentsOptions) {
		o.Index = index
	}
}

// Limit number of results.
func Limit(limit int) DocumentsOption {
	return func(o *DocumentsOptions) {
		o.Limit = limit
	}
}

// NoData don't return data.
func NoData() DocumentsOption {
	return func(o *DocumentsOptions) {
		o.NoData = true
	}
}
