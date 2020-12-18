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
