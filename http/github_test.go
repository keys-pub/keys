package http_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/http"
	"github.com/stretchr/testify/require"
)

func TestGithub(t *testing.T) {
	client := http.NewClient()
	urs := "https://gist.github.com/gabriel/ceea0f3b675bac03425472692273cf52"
	req, err := http.NewRequest("GET", urs, nil)
	require.NoError(t, err)
	res, err := client.Request(context.TODO(), req, nil)
	require.NoError(t, err)

	out, brand := encoding.FindSaltpack(string(res), true)
	require.Equal(t, "kdZaJI1U5AS7G6iVoUxdP8OtPzEoM6pYhVl0YQZJnotVEwLg9BDb5SUO05pmabUSeCvBfdPoRpPJ8wrcF5PP3wTCKq6Xr2MZHgg6m2QalgJCD6vMqlBQfIg6QsfB27aP5DMuXlJAUVIAvMDHIoptmSriNMzfpwBjRShVLWH70a0GOEqD6L8bkC5EFOwCedvHFpcAQVqULHjcSpeCfZEIOaQ2IP", out)
	require.Equal(t, "", brand)
}
