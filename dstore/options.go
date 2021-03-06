package dstore

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
	// Where
	Where *where
}

type where struct {
	Name  string
	Op    string
	Value interface{}
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

// Where name op value.
func Where(name string, op string, value interface{}) Option {
	return func(o *Options) {
		o.Where = &where{Name: name, Op: op, Value: value}
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

// SetOptions ...
type SetOptions struct {
	MergeAll bool
}

// SetOption ...
type SetOption func(*SetOptions)

// NewSetOptions parses Options.
func NewSetOptions(opts ...SetOption) SetOptions {
	var options SetOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// MergeAll merges values.
func MergeAll() SetOption {
	return func(o *SetOptions) {
		o.MergeAll = true
	}
}
