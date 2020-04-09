package keys_test

import (
	"encoding/json"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestSecretStore(t *testing.T) {
	kr := keyring.NewMem()
	ss := keys.NewSecretStore(kr)

	clock := newClock()
	ss.SetTimeNow(clock.Now)

	secret := &keys.Secret{
		ID:        "Ibgoe3sXvdpxFUeR1hSUriTRdxvcoWjou80WnPiFcPC",
		Name:      "keys.pub",
		Data:      []byte("testing"),
		CreatedAt: clock.Now(),
		UpdatedAt: clock.Now(),
	}

	b, err := json.Marshal(secret)
	require.NoError(t, err)
	expected := `{"id":"Ibgoe3sXvdpxFUeR1hSUriTRdxvcoWjou80WnPiFcPC","name":"keys.pub","data":"dGVzdGluZw==","createdAt":"2009-02-13T23:31:30.001Z","updatedAt":"2009-02-13T23:31:30.002Z"}`
	require.Equal(t, expected, string(b))

	err = ss.SaveSecret(secret)
	require.NoError(t, err)

	out, err := ss.Secret(secret.ID)
	require.NoError(t, err)
	require.Equal(t, out.Name, secret.Name)
	require.Equal(t, out.Data, secret.Data)
	require.Equal(t, out.CreatedAt, secret.CreatedAt)
	require.Equal(t, keys.TimeFromMillis(keys.TimeMs(1234567890003)), secret.UpdatedAt)

	secrets, err := ss.Secrets(nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(secrets))
	require.Equal(t, secrets[0].Name, secret.Name)
	require.Equal(t, secrets[0].Data, secret.Data)

	err = ss.SaveSecret(&keys.Secret{})
	require.EqualError(t, err, "no secret id")

}
