package request_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys/request"
	"github.com/stretchr/testify/require"
)

func TestReddit(t *testing.T) {
	// t.Skip()
	req := request.NewHTTPRequestor()

	urs := "https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json"
	_, err := req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
}
