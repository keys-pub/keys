package services_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/user/services"
	"github.com/stretchr/testify/require"
)

func TestProxy(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// services.SetLogger(user.NewLogger(user.DebugLevel))

	kid := keys.ID("kex1e26rq9vrhjzyxhep0c5ly6rudq7m2cexjlkgknl2z4lqf8ga3uasz3s48m")
	urs := "https://twitter.com/gabrlh/status/1222706272849391616"

	usr, err := user.New(kid, "twitter", "gabrlh", urs, 1)
	require.NoError(t, err)
	client := http.NewClient()
	result := services.Verify(context.TODO(), services.Proxy, client, usr)
	require.Equal(t, user.StatusOK, result.Status)
	expected := "BEGIN MESSAGE.\nEqcgDt8RfXvPq9b 4qCV8S3VPKIQKqa N7Rc1YruQQYuVS8 niHzUv7jdykkEPSrKGcJQCNTkNE7uF swPuwfpaZX6TCKq 6Xr2MZHgg6S0Mjg WFMJ1KHxazTuXs4icK3k8SZCR8mVLQ MSVhFeMrvz0qJOm A96zW9RAY6whsLo 5fC8i3fRJjyo9mQJZid8MwBXJl1XDL 5ZOSkLYs6sk6a2g CiGyA2IP.\nEND MESSAGE."
	require.Equal(t, expected, result.Statement)
}
