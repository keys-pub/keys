package secret_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/secret"
	"github.com/keys-pub/keys/util"
	"github.com/stretchr/testify/require"
)

type clock struct {
	t time.Time
}

func newClock() *clock {
	t := util.TimeFromMillis(1234567890000)
	return &clock{
		t: t,
	}
}

func (c *clock) Now() time.Time {
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

func TestSecretMarshal(t *testing.T) {
	kr := keyring.NewMem()
	ss := secret.NewStore(kr)

	clock := newClock()
	ss.SetTimeNow(clock.Now)

	secret := &secret.Secret{
		ID:        "Ibgoe3sXvdpxFUeR1hSUriTRdxvcoWjou80WnPiFcPC",
		Name:      "keys.pub",
		Username:  "gabriel@email.com",
		Password:  "12345", // Remind me to change my luggage combination
		Type:      secret.PasswordType,
		CreatedAt: clock.Now(),
		UpdatedAt: clock.Now(),
	}

	b, err := json.MarshalIndent(secret, "", "  ")
	require.NoError(t, err)
	expected := `{
  "id": "Ibgoe3sXvdpxFUeR1hSUriTRdxvcoWjou80WnPiFcPC",
  "name": "keys.pub",
  "type": "password",
  "username": "gabriel@email.com",
  "password": "12345",
  "createdAt": "2009-02-13T23:31:30.001Z",
  "updatedAt": "2009-02-13T23:31:30.002Z"
}`
	require.Equal(t, expected, string(b))
}

func TestSecretStoreSaveDefault(t *testing.T) {
	kr := keyring.NewMem()
	ss := secret.NewStore(kr)

	secret := &secret.Secret{
		ID:   "Ibgoe3sXvdpxFUeR1hSUriTRdxvcoWjou80WnPiFcPC",
		Type: secret.PasswordType,
	}

	out, updated, err := ss.Set(secret)
	require.NoError(t, err)
	require.False(t, updated)
	require.Equal(t, out.ID, secret.ID)
}
