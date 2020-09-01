package user_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/stretchr/testify/require"
)

// TODO: Remove after full re-index.

func TestSigchainIndexCompatibilityRevoke(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	req := request.NewMockRequestor()
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	sk := keys.GenerateEdX25519Key()
	kid := sk.ID()
	sc := keys.NewSigchain(kid)

	// User
	testTwitterSigchain(t, sk, "gabriel", sc, scs, req, clock)

	res, err := users.UpdateForTestingCompatibility(context.TODO(), kid)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, user.StatusOK, res.Status)
	require.Equal(t, "gabriel@twitter", res.User.ID())

	// Revoke
	_, err = sc.Revoke(1, sk)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	res, err = users.UpdateForTestingCompatibility(context.TODO(), kid)
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestSigchainIndexCompatibilityRevokeOldToNew(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	req := request.NewMockRequestor()
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	sk := keys.GenerateEdX25519Key()
	kid := sk.ID()
	sc := keys.NewSigchain(kid)

	// User
	testTwitterSigchain(t, sk, "gabriel", sc, scs, req, clock)

	result, err := users.UpdateForTestingCompatibility(context.TODO(), kid)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "gabriel@twitter", result.User.ID())

	// Revoke
	_, err = sc.Revoke(1, sk)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	res, err := users.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.Equal(t, 0, len(res))
}

func TestSigchainIndexCompatibilityOldToNew(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	req := request.NewMockRequestor()
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	sk := keys.GenerateEdX25519Key()
	kid := sk.ID()
	sc := keys.NewSigchain(kid)

	testTwitterSigchain(t, sk, "gabriel", sc, scs, req, clock)

	result, err := users.UpdateForTestingCompatibility(context.TODO(), kid)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "gabriel@twitter", result.User.ID())

	res, err := users.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.Equal(t, 1, len(res))
	require.Equal(t, user.StatusOK, res[0].Status)
	require.Equal(t, "gabriel@twitter", res[0].User.ID())
}

func TestSigchainIndexCompatibilityEmpty(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	req := request.NewMockRequestor()
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	sk := keys.GenerateEdX25519Key()
	kid := sk.ID()

	result, err := users.UpdateForTestingCompatibility(context.TODO(), kid)
	require.NoError(t, err)
	require.Nil(t, result)

	res, err := users.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.Equal(t, 0, len(res))
}
