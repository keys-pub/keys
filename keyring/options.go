package keyring

import "strings"

// Options ...
type Options struct {
	st Store
}

// Option ...
type Option func(*Options) error

// NewOptions ...
func NewOptions(opts ...Option) (Options, error) {
	var options Options
	for _, o := range opts {
		if err := o(&options); err != nil {
			return options, err
		}
	}
	return options, nil
}

// ListOption ...
type ListOption func(*ListOptions)

// ListOptions ...
type ListOptions struct {
	Types []string
}

// NewListOptions ...
func NewListOptions(opts ...ListOption) ListOptions {
	var options ListOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// WithTypes ...
func WithTypes(types ...string) ListOption {
	return func(o *ListOptions) {
		o.Types = types
	}
}

// IDsOptions ...
type IDsOptions struct {
	Prefix   string
	Hidden   bool
	Reserved bool
}

// IDsOption ...
type IDsOption func(*IDsOptions)

// NewIDsOptions ...
func NewIDsOptions(opts ...IDsOption) IDsOptions {
	var options IDsOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// WithPrefix ...
func WithPrefix(prefix string) IDsOption {
	return func(o *IDsOptions) {
		o.Prefix = prefix
	}
}

// WithReservedPrefix ...
func WithReservedPrefix(prefix string) IDsOption {
	if !strings.HasPrefix(prefix, ReservedPrefix) {
		prefix = reserved(prefix)
	}
	return func(o *IDsOptions) {
		o.Prefix = prefix
		o.Reserved = true
	}
}

// Hidden ...
func Hidden() IDsOption {
	return func(o *IDsOptions) {
		o.Hidden = true
	}
}

// Reserved ...
func Reserved() IDsOption {
	return func(o *IDsOptions) {
		o.Reserved = true
	}
}
