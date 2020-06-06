package secret_test

import (
	"encoding/json"
	"testing"

	"github.com/keys-pub/keys/secret"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestSecretStore(t *testing.T) {
	kr := testMem(t, true)
	ss := secret.NewStore(kr)

	clock := tsutil.NewClock()
	ss.SetTimeNow(clock.Now)

	out, err := ss.Get(secret.RandID())
	require.NoError(t, err)
	require.Nil(t, out)

	sec := &secret.Secret{
		ID:        "Ibgoe3sXvdpxFUeR1hSUriTRdxvcoWjou80WnPiFcPC",
		Name:      "keys.pub",
		Username:  "gabriel@email.com",
		Password:  "12345", // Remind me to change my luggage combination
		Type:      secret.PasswordType,
		CreatedAt: clock.Now(),
		UpdatedAt: clock.Now(),
	}

	out, updated, err := ss.Set(sec)
	require.NoError(t, err)
	require.False(t, updated)
	require.Equal(t, out.ID, sec.ID)

	out2, err := ss.Get(sec.ID)
	require.NoError(t, err)
	b, err := json.MarshalIndent(out2, "", "  ")
	require.NoError(t, err)
	expected := `{
  "id": "Ibgoe3sXvdpxFUeR1hSUriTRdxvcoWjou80WnPiFcPC",
  "name": "keys.pub",
  "type": "password",
  "username": "gabriel@email.com",
  "password": "12345",
  "createdAt": "2009-02-13T23:31:30.003Z",
  "updatedAt": "2009-02-13T23:31:30.003Z"
}`
	require.Equal(t, expected, string(b))

	secrets, err := ss.List()
	require.NoError(t, err)
	require.Equal(t, 1, len(secrets))
	require.Equal(t, secrets[0].Name, sec.Name)
	require.Equal(t, secrets[0].Password, sec.Password)

	out2.Password = "mybetternewpassword"
	out3, updated, err := ss.Set(out2)
	require.NoError(t, err)
	require.True(t, updated)

	out4, err := ss.Get(out3.ID)
	require.NoError(t, err)
	b4, err := json.MarshalIndent(out4, "", "  ")
	require.NoError(t, err)
	expected4 := `{
  "id": "Ibgoe3sXvdpxFUeR1hSUriTRdxvcoWjou80WnPiFcPC",
  "name": "keys.pub",
  "type": "password",
  "username": "gabriel@email.com",
  "password": "mybetternewpassword",
  "createdAt": "2009-02-13T23:31:30.003Z",
  "updatedAt": "2009-02-13T23:31:30.004Z"
}`
	require.Equal(t, expected4, string(b4))

	_, _, err = ss.Set(&secret.Secret{})
	require.EqualError(t, err, "no secret id")
}
