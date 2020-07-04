package docs

// Options ...
type Options struct {
	// Prefix to filter on.
	Prefix string
	// Index is offset into number of documents.
	Index int
	// Limit is number of documents (max) to return.
	Limit int
	// NoData to only include only path in Document (no data).
	NoData bool
}

// Option ...
type Option func(*Options)

// NewOptions parses Options.
func NewOptions(opts ...Option) Options {
	var options Options
	for _, o := range opts {
		o(&options)
	}
	return options
}

// Prefix to list.
func Prefix(prefix string) Option {
	return func(o *Options) {
		o.Prefix = prefix
	}
}

// Index to start at.
func Index(index int) Option {
	return func(o *Options) {
		o.Index = index
	}
}

// Limit number of results.
func Limit(limit int) Option {
	return func(o *Options) {
		o.Limit = limit
	}
}

// NoData don't return data.
func NoData() Option {
	return func(o *Options) {
		o.NoData = true
	}
}
