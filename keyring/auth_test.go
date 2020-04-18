package keyring_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	// keyring.SetLogger(keyring.NewLogger(keyring.DebugLevel))

	kr, err := keyring.NewKeyring("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	testAuth(t, kr)
}

func testAuth(t *testing.T, kr keyring.Keyring) {
	isSetup, err := kr.IsSetup()
	require.NoError(t, err)
	require.False(t, isSetup)

	salt := bytes.Repeat([]byte{0x01}, 32)
	auth, err := keyring.NewPasswordAuth("test", "password123", salt)
	require.NoError(t, err)

	// Unlock (error)
	err = kr.Unlock(auth)
	require.EqualError(t, err, "invalid keyring auth")

	// Invalid auth
	invalid, err := keyring.NewPasswordAuth("", "password123", salt)
	require.NoError(t, err)
	err = kr.Setup(invalid)
	require.EqualError(t, err, "no auth name")
	_, err = keyring.NewPasswordAuth("test", "", salt)
	require.EqualError(t, err, "no password")

	// Setup
	err = kr.Setup(auth)
	require.NoError(t, err)

	isSetup, err = kr.IsSetup()
	require.NoError(t, err)
	require.True(t, isSetup)

	// Setup (again)
	err = kr.Setup(auth)
	require.EqualError(t, err, "keyring is already setup")

	err = kr.Unlock(auth)
	require.NoError(t, err)

	item := keyring.NewItem("key1", []byte("secret"), "", time.Now())
	err = kr.Create(item)
	require.NoError(t, err)

	item, err = kr.Get("key1")
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, "key1", item.ID)
	require.Equal(t, []byte("secret"), item.Data)

	err = kr.Lock()
	require.NoError(t, err)

	// Provision
	auth2, err := keyring.NewPasswordAuth("test2", "diffpassword", salt)
	require.NoError(t, err)

	err = kr.Provision(auth2)
	require.EqualError(t, err, "keyring is locked")
	_, err = kr.Deprovision(auth2)
	require.EqualError(t, err, "keyring is locked")

	err = kr.Unlock(auth)
	require.NoError(t, err)

	err = kr.Provision(auth2)
	require.NoError(t, err)

	// Test both succeed
	err = kr.Lock()
	require.NoError(t, err)
	err = kr.Unlock(auth)
	require.NoError(t, err)
	err = kr.Lock()
	require.NoError(t, err)
	err = kr.Unlock(auth2)
	require.NoError(t, err)

	// Deprovision
	ok, err := kr.Deprovision(auth2)
	require.NoError(t, err)
	require.True(t, ok)

	err = kr.Unlock(auth2)
	require.EqualError(t, err, "invalid keyring auth")

	// Test wrong password
	wrongpass, err := keyring.NewPasswordAuth("test", "invalidpassword", salt)
	require.NoError(t, err)
	err = kr.Unlock(wrongpass)
	require.EqualError(t, err, "invalid keyring auth")

	// Test get reserved
	_, err = kr.Get("#auth")
	require.EqualError(t, err, "keyring id prefix reserved #auth")

}

func TestSystemStore(t *testing.T) {
	kr, err := keyring.NewKeyring("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	salt := bytes.Repeat([]byte{0x01}, 32)
	auth, err := keyring.NewPasswordAuth("test", "password123", salt)
	require.NoError(t, err)
	err = kr.Setup(auth)
	require.NoError(t, err)

	st := keyring.SystemOrFS()

	kh, err := st.Get("KeysTest", "#auth-test")
	require.NoError(t, err)
	require.NotNil(t, kh)

	err = st.Set("KeysTest", ".raw", []byte{0x01}, "")
	require.NoError(t, err)

	_, err = kr.Get(".raw")
	require.EqualError(t, err, "invalid keyring auth")
}

func TestAuthUpgrade(t *testing.T) {
	// keyring.SetLogger(keyring.NewLogger(keyring.DebugLevel))

	st := keyring.SystemOrFS()
	// Save old key
	key := rand32()
	oldItem := keyring.NewItem("#auth", key[:], "", time.Now())
	err := keyring.TestSetItem(st, "KeysTest", oldItem, key)
	require.NoError(t, err)

	kr, err := keyring.NewKeyring("KeysTest", st)
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	err = kr.Unlock(keyring.NewKeyAuth("app", key))
	require.NoError(t, err)

	err = kr.Unlock(keyring.NewKeyAuth("app", key))
	require.NoError(t, err)
}
