package request_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys/request"
	"github.com/stretchr/testify/require"
)

func TestReddit(t *testing.T) {
	req := request.NewHTTPRequestor()
	urs := "https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json"
	res, err := req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
	require.NotEmpty(t, res)
}

func TestTwitter(t *testing.T) {
	req := request.NewHTTPRequestor()
	urs := "https://mobile.twitter.com/gabrlh/status/1222706272849391616"
	res, err := req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
	require.NotEmpty(t, res)
}

func TestTwitterRedirect(t *testing.T) {
	req := request.NewHTTPRequestor()
	// Redirect (from lowercase) to /Boboloblaws/status/1276948233915207680 is ok
	urs := "https://mobile.twitter.com/boboloblaws/status/1276948233915207680"
	res, err := req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
	require.NotEmpty(t, res)

	// Tweet ID from different user, should not redirect
	urs = "https://mobile.twitter.com/boboloblaws/status/1222706272849391616"
	res, err = req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
	require.Empty(t, res)
}

func TestGithub(t *testing.T) {
	req := request.NewHTTPRequestor()
	urs := "https://gist.github.com/gabriel/ceea0f3b675bac03425472692273cf52"
	res, err := req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
	require.NotEmpty(t, res)
}
