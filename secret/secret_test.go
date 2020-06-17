package secret_test

import (
	"encoding/json"
	"testing"

	"github.com/keys-pub/keys/secret"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestSecretID(t *testing.T) {
	id := secret.RandID()
	require.Equal(t, 43, len(id))
}

func TestSecretMarshal(t *testing.T) {
	clock := tsutil.NewClock()

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
