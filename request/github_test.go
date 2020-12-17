package request_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/request"
	"github.com/stretchr/testify/require"
)

func TestGithub(t *testing.T) {
	req := request.NewHTTPRequestor()
	urs := "https://gist.github.com/gabriel/ceea0f3b675bac03425472692273cf52"
	res, err := req.RequestURLString(context.TODO(), urs, nil)
	require.NoError(t, err)

	out, brand := encoding.FindSaltpack(string(res), true)
	require.Equal(t, "kdZaJI1U5AS7G6iVoUxdP8OtPzEoM6pYhVl0YQZJnotVEwLg9BDb5SUO05pmabUSeCvBfdPoRpPJ8wrcF5PP3wTCKq6Xr2MZHgg6m2QalgJCD6vMqlBQfIg6QsfB27aP5DMuXlJAUVIAvMDHIoptmSriNMzfpwBjRShVLWH70a0GOEqD6L8bkC5EFOwCedvHFpcAQVqULHjcSpeCfZEIOaQ2IP", out)
	require.Equal(t, "", brand)
}
