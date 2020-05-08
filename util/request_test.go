package util_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys/util"
	"github.com/stretchr/testify/require"
)

func TestReddit(t *testing.T) {
	t.Skip()
	req := util.NewHTTPRequestor()

	urs := "https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json"
	_, err := req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
}
