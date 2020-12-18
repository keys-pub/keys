package user_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/user"
	"github.com/stretchr/testify/require"
)

func TestGithub(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// services.SetLogger(user.NewLogger(user.DebugLevel))

	kid := keys.ID("kex1mnseg28xu6g3j4wur7hqwk8ag3fu3pmr2t5lync26xmgff0dtryqupf80c")
	urs := "https://gist.github.com/gabriel/ceea0f3b675bac03425472692273cf52"

	usr, err := user.New(kid, "github", "gabriel", urs, 1)
	require.NoError(t, err)
	result := usr.RequestVerify(context.TODO())
	require.Equal(t, user.StatusOK, result.Status)
}
