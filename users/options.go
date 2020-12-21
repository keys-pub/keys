package users

import (
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
)

// Options are options for Users.
type Options struct {
	Client http.Client
	Clock  tsutil.Clock
}

// Option ...
type Option func(*Options)

func newOptions(opts ...Option) Options {
	var options Options
	for _, o := range opts {
		o(&options)
	}
	if options.Client == nil {
		options.Client = http.NewClient()
	}
	if options.Clock == nil {
		options.Clock = tsutil.NewClock()
	}
	return options
}

// Client to use.
func Client(client http.Client) Option {
	return func(o *Options) {
		o.Client = client
	}
}

// Clock to use.
func Clock(clock tsutil.Clock) Option {
	return func(o *Options) {
		o.Clock = clock
	}
}

// UpdateOptions ...
type UpdateOptions struct {
	UseTwitterProxy bool
	IsCreate        bool
}

// UpdateOption ...
type UpdateOption func(*UpdateOptions)

func newUpdateOptions(opts ...UpdateOption) UpdateOptions {
	var options UpdateOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// UseTwitterProxy option.
func UseTwitterProxy() UpdateOption {
	return func(o *UpdateOptions) {
		o.UseTwitterProxy = true
	}
}

// IsCreate option.
func IsCreate() UpdateOption {
	return func(o *UpdateOptions) {
		o.IsCreate = true
	}
}
