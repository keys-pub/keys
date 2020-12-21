package users

import "github.com/keys-pub/keys/user/services"

// LookupService finds service using options.
func LookupService(service string, opt ...UpdateOption) (services.Service, error) {
	opts := newUpdateOptions(opt...)

	// If twitter proxy is enabled, we'll used cached values from keys.pub, or
	// if creating a user, check with the proxy which returns realtime values.
	if service == "twitter" && opts.UseTwitterProxy {
		if opts.IsCreate {
			return services.Proxy, nil
		}
		return services.KeysPub, nil
	}

	return services.Lookup(service)
}
