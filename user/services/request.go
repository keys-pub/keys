package services

import (
	"context"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
)

// Request resource.
func Request(ctx context.Context, client http.Client, urs string, headers []http.Header) (user.Status, []byte, error) {
	req, err := http.NewRequest("GET", urs, nil)
	if err != nil {
		return user.StatusFailure, nil, err
	}
	b, err := client.Request(ctx, req, headers)
	if err != nil {
		if errHTTP, ok := errors.Cause(err).(http.Error); ok && errHTTP.StatusCode == 404 {
			return user.StatusResourceNotFound, nil, errors.Errorf("resource not found")
		}
		return user.StatusConnFailure, nil, err
	}
	return user.StatusOK, b, nil
}
