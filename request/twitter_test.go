package request_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/request"
	"github.com/stretchr/testify/require"
)

func TestTwitter(t *testing.T) {
	req := request.NewHTTPRequestor()
	urs := "https://mobile.twitter.com/gabrlh/status/1222706272849391616"
	res, err := req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)

	out, brand := encoding.FindSaltpack(string(res), true)
	require.Equal(t, "EqcgDt8RfXvPq9b4qCV8S3VPKIQKqaN7Rc1YruQQYuVS8niHzUv7jdykkEPSrKGcJQCNTkNE7uFswPuwfpaZX6TCKq6Xr2MZHgg6S0MjgWFMJ1KHxazTuXs4icK3k8SZCR8mVLQMSVhFeMrvz0qJOmA96zW9RAY6whsLo5fC8i3fRJjyo9mQJZid8MwBXJl1XDL5ZOSkLYs6sk6a2gCiGyA2IP", out)
	require.Equal(t, "", brand)
}

func TestTwitterRedirect(t *testing.T) {
	req := request.NewHTTPRequestor()
	// Redirect (from lowercase) to /Boboloblaws/status/1306608574257197058 is ok
	urs := "https://mobile.twitter.com/boboloblaws/status/1306608574257197058"
	res, err := req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
	out, brand := encoding.FindSaltpack(string(res), true)
	require.Equal(t, "Y8Rk7O43uVYNtOFT3e1VBj8PYoopsALmaIKmY7xPlHTQLRVzZuq7T21t7gh5hkcwWzDn4tOGVbuKYg7qzIvzSQTCKq6Xr2MZHgg702h9QYi2QPylekc6hgqBIuxIzo9V4PTT6y5dakSFOgwtjBEgO3JDRSAcmA9ILQuPDUFYbmAZPti6SXkYku6v0X3IpV4aoEmdOi8RotFfpxttDvoSraB2BwmNTeOh3", out)
	require.Equal(t, "", brand)

	// Tweet ID from different user, should not redirect
	urs = "https://mobile.twitter.com/boboloblaws/status/1222706272849391616"
	res, err = req.RequestURLString(context.TODO(), urs)
	require.NoError(t, err)
	require.Empty(t, res)
}
