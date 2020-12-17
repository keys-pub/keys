package user

import (
	"github.com/keys-pub/keys/link"
	"github.com/pkg/errors"
)

func lookupService(service string) (link.Service, error) {
	s, _ := services[service]
	if s == nil {
		return nil, errors.Errorf("service not found: %s", service)
	}
	return s, nil
}

// AddService enables a service.
func AddService(service link.Service) {
	services[service.ID()] = service
}

var services = map[string]link.Service{}
