package user_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/user"
	"github.com/stretchr/testify/require"
)

func TestMyTwitter(t *testing.T) {
	kid := keys.ID("kex1e26rq9vrhjzyxhep0c5ly6rudq7m2cexjlkgknl2z4lqf8ga3uasz3s48m")
	urs := "https://twitter.com/gabrlh/status/1222706272849391616"

	usr, err := user.New(kid, "twitter", "gabrlh", urs, 1)
	require.NoError(t, err)
	result := usr.RequestVerify(context.TODO())
	require.Equal(t, user.StatusOK, result.Status)
}
