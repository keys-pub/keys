package keyring_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	kr, err := keyring.New("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	testAuth(t, kr)
}

func testAuth(t *testing.T, kr *keyring.Keyring) {
	isSetup, err := kr.IsSetup()
	require.NoError(t, err)
	require.False(t, isSetup)

	salt := bytes.Repeat([]byte{0x01}, 32)
	auth, err := keyring.NewPasswordAuth("password123", salt)
	require.NoError(t, err)

	// Unlock (error)
	_, err = kr.Unlock(auth)
	require.EqualError(t, err, "invalid keyring auth")

	// Invalid auth
	_, err = keyring.NewPasswordAuth("", salt)
	require.EqualError(t, err, "empty password")

	// Setup
	id, err := kr.Setup(auth)
	require.NoError(t, err)

	isSetup, err = kr.IsSetup()
	require.NoError(t, err)
	require.True(t, isSetup)

	// Setup (again)
	_, err = kr.Setup(auth)
	require.EqualError(t, err, "keyring is already setup")

	// Lock
	err = kr.Lock()
	require.NoError(t, err)

	_, err = kr.Unlock(auth)
	require.NoError(t, err)

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
	ids, err := kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, []string{id}, ids)

	// Provision
	auth2, err := keyring.NewPasswordAuth("diffpassword", salt)
	require.NoError(t, err)
	_, err = kr.Provision(auth2)
	require.EqualError(t, err, "keyring is locked")
	_, err = kr.Unlock(auth)
	require.NoError(t, err)
	id2, err := kr.Provision(auth2)
	require.NoError(t, err)
	require.NotEmpty(t, id2)

	// Test both succeed
	err = kr.Lock()
	require.NoError(t, err)
	_, err = kr.Unlock(auth)
	require.NoError(t, err)
	err = kr.Lock()
	require.NoError(t, err)
	_, err = kr.Unlock(auth2)
	require.NoError(t, err)

	// Deprovision
	ok, err := kr.Deprovision(id2)
	require.NoError(t, err)
	require.True(t, ok)

	_, err = kr.Unlock(auth2)
	require.EqualError(t, err, "invalid keyring auth")

	// Test wrong password
	wrongpass, err := keyring.NewPasswordAuth("invalidpassword", salt)
	require.NoError(t, err)
	_, err = kr.Unlock(wrongpass)
	require.EqualError(t, err, "invalid keyring auth")

	// Test get reserved
	_, err = kr.Get("#auth")
	require.EqualError(t, err, "keyring id prefix reserved #auth")

	// Test invalid password
	auth3, err := keyring.NewPasswordAuth("invalidpassword", salt)
	require.NoError(t, err)
	_, err = kr.Unlock(auth3)
	require.EqualError(t, err, "invalid keyring auth")
}

func TestSystemStore(t *testing.T) {
	kr, err := keyring.New("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	salt := bytes.Repeat([]byte{0x01}, 32)
	auth, err := keyring.NewPasswordAuth("password123", salt)
	require.NoError(t, err)
	id, err := kr.Setup(auth)
	require.NoError(t, err)

	st := keyring.SystemOrFS()

	mk, err := st.Get("KeysTest", id)
	require.NoError(t, err)
	require.NotNil(t, mk)

	err = st.Set("KeysTest", ".raw", []byte{0x01})
	require.NoError(t, err)

	_, err = kr.Get(".raw")
	require.EqualError(t, err, "invalid keyring auth")
}
