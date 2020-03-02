package keys_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestReddit(t *testing.T) {
	t.Skip()
	req := keys.NewHTTPRequestor()

	ur, err := url.Parse("https://reddit.com/r/keyspubmsgs/comments/f8g9vd/gabrlh.json")
	require.NoError(t, err)

	_, err = req.RequestURL(context.TODO(), ur)
	require.NoError(t, err)
}
