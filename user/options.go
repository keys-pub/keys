package user

import (
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
)

// UsersOptions are options for Users.
type UsersOptions struct {
	Req   request.Requestor
	Clock tsutil.Clock
}

// UsersOption ...
type UsersOption func(*UsersOptions)

func newUserOptions(opts ...UsersOption) UsersOptions {
	var options UsersOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// Requestor to use.
func Requestor(req request.Requestor) UsersOption {
	return func(o *UsersOptions) {
		o.Req = req
	}
}

// Clock to use.
func Clock(clock tsutil.Clock) UsersOption {
	return func(o *UsersOptions) {
		o.Clock = clock
	}
}
