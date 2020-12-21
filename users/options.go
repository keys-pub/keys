package users

import (
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/user/services"
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

// ServiceLookupFn for custom service lookup.
type ServiceLookupFn func(usr *user.User) services.Service

// UpdateOptions ...
type UpdateOptions struct {
	// Specify the service to use for the check.
	// For twitter proxy, use services.Proxy.
	Service ServiceLookupFn
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

// UseService option.
func UseService(service ServiceLookupFn) UpdateOption {
	return func(o *UpdateOptions) {
		o.Service = service
	}
}
