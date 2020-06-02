package keyring_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	kr, err := keyring.New(keyring.SystemOrFS("KeysTest"))
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	testAuth(t, kr)
}

func testAuth(t *testing.T, kr *keyring.Keyring) {
	status, err := kr.Status()
	require.NoError(t, err)
	require.Equal(t, keyring.Setup, status)

	salt := bytes.Repeat([]byte{0x01}, 32)
	key, err := keyring.KeyForPassword("password123", salt)
	require.NoError(t, err)

	// Unlock (error)
	_, err = kr.Unlock(key)
	require.EqualError(t, err, "invalid keyring auth")

	// Invalid auth
	_, err = keyring.KeyForPassword("", salt)
	require.EqualError(t, err, "empty password")

	// Setup
	provision := keyring.NewProvision(keyring.UnknownAuth)
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	status, err = kr.Status()
	require.NoError(t, err)
	require.Equal(t, keyring.Unlocked, status)

	// Setup (again)
	err = kr.Setup(key, provision)
	require.EqualError(t, err, "keyring is already setup")

	// Lock
	err = kr.Lock()
	require.NoError(t, err)

	status, err = kr.Status()
	require.NoError(t, err)
	require.Equal(t, keyring.Locked, status)

	_, err = kr.Unlock(key)
	require.NoError(t, err)

	status, err = kr.Status()
	require.NoError(t, err)
	require.Equal(t, keyring.Unlocked, status)

	// Create item
	item := keyring.NewItem("key1", []byte("secret"), "", time.Now())
	err = kr.Create(item)
	require.NoError(t, err)

	item, err = kr.Get("key1")
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, "key1", item.ID)
	require.Equal(t, []byte("secret"), item.Data)

	// Lock
	err = kr.Lock()
	require.NoError(t, err)

	// Check provisions
	mds, err := kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, 1, len(mds))
	require.Equal(t, provision.ID, mds[0].ID)

	// Provision
	provision2 := keyring.NewProvision(keyring.UnknownAuth)
	key2, err := keyring.KeyForPassword("diffpassword", salt)
	require.NoError(t, err)
	err = kr.Provision(key2, provision2)
	require.EqualError(t, err, "keyring is locked")
	_, err = kr.Unlock(key)
	require.NoError(t, err)
	err = kr.Provision(key2, provision2)
	require.NoError(t, err)

	// Test both succeed
	err = kr.Lock()
	require.NoError(t, err)
	_, err = kr.Unlock(key)
	require.NoError(t, err)
	err = kr.Lock()
	require.NoError(t, err)
	_, err = kr.Unlock(key2)
	require.NoError(t, err)

	// Deprovision
	ok, err := kr.Deprovision(provision2.ID)
	require.NoError(t, err)
	require.True(t, ok)

	_, err = kr.Unlock(key2)
	require.EqualError(t, err, "invalid keyring auth")

	// Test wrong password
	wrongpass, err := keyring.KeyForPassword("invalidpassword", salt)
	require.NoError(t, err)
	_, err = kr.Unlock(wrongpass)
	require.EqualError(t, err, "invalid keyring auth")

	// Test get reserved
	_, err = kr.Get("#auth")
	require.EqualError(t, err, "keyring id prefix reserved #auth")
}

func TestSystemStore(t *testing.T) {
	kr, err := keyring.New(keyring.SystemOrFS("KeysTest"))
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	salt := bytes.Repeat([]byte{0x01}, 32)

	provision := keyring.NewProvision(keyring.UnknownAuth)
	key, err := keyring.KeyForPassword("password123", salt)
	require.NoError(t, err)
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	st, err := keyring.NewSystemOrFS("KeysTest")
	require.NoError(t, err)

	mk, err := st.Get("#auth-" + provision.ID)
	require.NoError(t, err)
	require.NotNil(t, mk)

	err = st.Set(".raw", []byte{0x01})
	require.NoError(t, err)

	_, err = kr.Get(".raw")
	require.EqualError(t, err, "invalid keyring auth")
}

func TestAuthV1(t *testing.T) {
	kr, err := keyring.New(keyring.SystemOrFS("KeysTest"))
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	salt := bytes.Repeat([]byte{0x01}, 32)
	key, err := keyring.KeyForPassword("password123", salt)
	require.NoError(t, err)

	// Set auth the old way
	item := keyring.NewItem("#auth", key[:], "", time.Now())
	b, err := item.Encrypt(key)
	require.NoError(t, err)
	err = kr.Store().Set("#auth", b)
	require.NoError(t, err)

	// Unlock with old auth
	_, err = kr.Unlock(key)
	require.NoError(t, err)

	provisions, err := kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, 1, len(provisions))
	require.Equal(t, "v1.auth", provisions[0].ID)
}
