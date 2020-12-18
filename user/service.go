package user

import (
	"github.com/keys-pub/keys/user/services"
	"github.com/pkg/errors"
)

// LookupService returns service (added by AddService).
func LookupService(service string) (services.Service, error) {
	s, ok := enabledServices[service]
	if !ok || s == nil {
		return nil, errors.Errorf("service not found: %s", service)
	}
	return s, nil
}

// AddService enables a service.
func AddService(service services.Service) {
	enabledServices[service.ID()] = service
}

var enabledServices = map[string]services.Service{}
