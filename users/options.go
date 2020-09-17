package users

import (
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
)

// Options are options for Users.
type Options struct {
	Req   request.Requestor
	Clock tsutil.Clock
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

// Requestor to use.
func Requestor(req request.Requestor) Option {
	return func(o *Options) {
		o.Req = req
	}
}

// Clock to use.
func Clock(clock tsutil.Clock) Option {
	return func(o *Options) {
		o.Clock = clock
	}
}
