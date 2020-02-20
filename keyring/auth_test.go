package keyring_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	kr, err := keyring.NewKeyring("KeysTest")
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	testAuth(t, kr)
}

func testAuth(t *testing.T, kr keyring.Keyring) {
	authed, err := kr.Authed()
	require.NoError(t, err)
	require.False(t, authed)

	salt := bytes.Repeat([]byte{0x01}, 32)
	auth, err := keyring.NewPasswordAuth("password123", salt)
	require.NoError(t, err)
	err = kr.Unlock(auth)
	require.NoError(t, err)

	authed2, err := kr.Authed()
	require.NoError(t, err)
	require.True(t, authed2)

	item := keyring.NewItem("key1", keyring.NewStringSecret("secret"), "")
	err = kr.Set(item)
	require.NoError(t, err)

	item, err = kr.Get("key1")
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, "key1", item.ID)
	require.Equal(t, []byte("secret"), item.Secret().Data)

	// Test get reserved
	_, err = kr.Get("#auth")
	require.EqualError(t, err, "keyring id prefix reserved #auth")

	// Test invalid password
	auth2, err := keyring.NewPasswordAuth("invalidpassword", salt)
	require.NoError(t, err)
	err = kr.Unlock(auth2)
	require.EqualError(t, err, "invalid keyring auth")

	// // Reset auth, then unlock
	// reerr := kr.ResetAuth()
	// require.NoError(t, reerr)
	// authed3, err := kr.Authed()
	// require.NoError(t, err)
	// require.False(t, authed3)
	// err := kr.Unlock(auth)
	// require.NoError(t, err)

	// item, err = kr.Get("key1")
	// require.NoError(t, err)
	// require.NotNil(t, item)
	// require.Equal(t, "key1", item.ID)
	// require.Equal(t, []byte("secret"), item.Secret().Data)
}

func TestStore(t *testing.T) {
	kr, err := keyring.NewKeyring("KeysTest")
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	salt := bytes.Repeat([]byte{0x01}, 32)
	auth, err := keyring.NewPasswordAuth("password123", salt)
	require.NoError(t, err)
	err = kr.Unlock(auth)
	require.NoError(t, err)

	st := keyring.NewStore()

	kh, err := st.Get("KeysTest", "#auth")
	require.NoError(t, err)
	require.NotNil(t, kh)

	err = st.Set("KeysTest", ".raw", []byte{0x01}, "")
	require.NoError(t, err)

	_, err = kr.Get(".raw")
	require.EqualError(t, err, "not an encoded keyring item")
}
