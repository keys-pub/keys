package keyring

// ListOption ...
type ListOption func(*ListOptions)

// ListOptions ...
type ListOptions struct {
	Types []string
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

// WithPrefix ...
func WithPrefix(prefix string) IDsOption {
	return func(o *IDsOptions) {
		o.Prefix = prefix
	}
}

// WithReservedPrefix ...
func WithReservedPrefix(prefix string) IDsOption {
	return func(o *IDsOptions) {
		o.Prefix = reserved(prefix)
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
