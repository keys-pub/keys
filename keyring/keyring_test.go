package keyring_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
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

func TestKeyring(t *testing.T) {
	kr, err := keyring.NewKeyring("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	testKeyring(t, kr)
}

func testKeyring(t *testing.T, kr keyring.Keyring) {
	salt := bytes.Repeat([]byte{0x01}, 32)
	auth, err := keyring.NewPasswordAuth("password123", salt)
	require.NoError(t, err)

	err = kr.Unlock(auth)
	require.NoError(t, err)

	// List
	items, err := kr.List(nil)
	require.NoError(t, err)
	require.Equal(t, 0, len(items))

	item, err := kr.Get("abc")
	require.NoError(t, err)
	require.Nil(t, item)

	now := time.Now()

	// Update missing ErrItemNotFound
	err = kr.Update("abc", []byte("password"))
	require.Equal(t, err, keyring.ErrItemNotFound)

	// Create
	err = kr.Create(keyring.NewItem("abc", []byte("password"), "type1", now))
	require.NoError(t, err)

	item, err = kr.Get("abc")
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, "abc", item.ID)
	require.Equal(t, []byte("password"), item.Data)
	require.Equal(t, util.TimeToMillis(now), util.TimeToMillis(item.CreatedAt))

	has, err := kr.Exists("abc")
	require.NoError(t, err)
	require.True(t, has)

	has2, err := kr.Exists("xyz")
	require.NoError(t, err)
	require.False(t, has2)

	// Create exising ErrItemAlreadyExists
	err = kr.Create(keyring.NewItem("abc", []byte("password"), "type1", now))
	require.Equal(t, err, keyring.ErrItemAlreadyExists)

	// Update
	err = kr.Update("abc", []byte("newpassword"))
	require.NoError(t, err)

	item, err = kr.Get("abc")
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, "abc", item.ID)
	require.Equal(t, []byte("newpassword"), item.Data)
	require.Equal(t, util.TimeToMillis(now), util.TimeToMillis(item.CreatedAt))

	// Create (hidden)
	err = kr.Create(keyring.NewItem(".ck", []byte("password"), "", time.Now()))
	require.NoError(t, err)

	// Create "xyz"
	err = kr.Create(keyring.NewItem("xyz", []byte("xpassword"), "type2", time.Now()))
	require.NoError(t, err)

	// List
	items, err = kr.List(nil)
	require.NoError(t, err)
	require.Equal(t, 2, len(items))
	require.Equal(t, items[0].ID, "abc")
	require.Equal(t, items[1].ID, "xyz")

	items2, err := kr.List(&keyring.ListOpts{Types: []string{"type2"}})
	require.NoError(t, err)
	require.Equal(t, 1, len(items2))
	require.Equal(t, items2[0].ID, "xyz")

	// Delete
	ok, err := kr.Delete("abc")
	require.NoError(t, err)
	require.True(t, ok)

	item3, err := kr.Get("abc")
	require.NoError(t, err)
	require.Nil(t, item3)

	has3, err := kr.Exists("abc")
	require.NoError(t, err)
	require.False(t, has3)

	ok2, err := kr.Delete("abc")
	require.NoError(t, err)
	require.False(t, ok2)
}

func TestReset(t *testing.T) {
	kr, err := keyring.NewKeyring("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	testReset(t, kr)
}

func testReset(t *testing.T, kr keyring.Keyring) {
	salt := bytes.Repeat([]byte{0x01}, 32)
	auth, err := keyring.NewPasswordAuth("password123", salt)
	require.NoError(t, err)

	err = kr.Unlock(auth)
	require.NoError(t, err)

	err = kr.Create(keyring.NewItem("key1", []byte("password"), "", time.Now()))
	require.NoError(t, err)

	salt, err = kr.Salt()
	require.NoError(t, err)

	salt2, err := kr.Salt()
	require.NoError(t, err)
	require.Equal(t, salt, salt2)

	reerr := kr.Reset()
	require.NoError(t, reerr)

	err = kr.Create(keyring.NewItem("key1", []byte("password"), "", time.Now()))
	require.EqualError(t, err, "keyring is locked")

	authed, err := kr.Authed()
	require.NoError(t, err)
	require.False(t, authed)

	salt3, err := kr.Salt()
	require.NoError(t, err)
	require.NotEqual(t, salt, salt3)

	auth2, err := keyring.NewPasswordAuth("newpassword123", salt)
	require.NoError(t, err)
	err = kr.Unlock(auth2)
	require.NoError(t, err)

	require.NotEqual(t, auth.Key(), auth2.Key())
}

func TestUnlock(t *testing.T) {
	kr, err := keyring.NewKeyring("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	testUnlock(t, kr)
}

func testUnlock(t *testing.T, kr keyring.Keyring) {
	err := kr.Create(keyring.NewItem("key1", []byte("password"), "", time.Now()))
	require.EqualError(t, err, "keyring is locked")

	_, err = kr.Get("key1")
	require.EqualError(t, err, "keyring is locked")

	_, err = kr.List(nil)
	require.EqualError(t, err, "keyring is locked")

	key := bytes32(bytes.Repeat([]byte{0x01}, 32))
	err = kr.Unlock(keyring.NewKeyAuth(key))
	require.NoError(t, err)

	err = kr.Create(keyring.NewItem("key1", []byte("password"), "", time.Now()))
	require.NoError(t, err)

	err = kr.Lock()
	require.NoError(t, err)

	_, err = kr.List(nil)
	require.EqualError(t, err, "keyring is locked")

	ok, err := kr.Exists("key1")
	require.NoError(t, err)
	require.True(t, ok)

	del, err := kr.Delete("key1")
	require.NoError(t, err)
	require.True(t, del)
}

func TestSetErrors(t *testing.T) {
	kr, err := keyring.NewKeyring("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	key := bytes32(bytes.Repeat([]byte{0x01}, 32))
	err = kr.Unlock(keyring.NewKeyAuth(key))
	require.NoError(t, err)

	err = kr.Create(keyring.NewItem("", nil, "", time.Time{}))
	require.EqualError(t, err, "no id")
}

func TestReserved(t *testing.T) {
	kr, err := keyring.NewKeyring("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	testReserved(t, kr)
}

func testReserved(t *testing.T, kr keyring.Keyring) {
	key := bytes32(bytes.Repeat([]byte{0x01}, 32))
	err := kr.Unlock(keyring.NewKeyAuth(key))
	require.NoError(t, err)

	_, err = kr.Get("#key")
	require.EqualError(t, err, "keyring id prefix reserved #key")
	_, err = kr.Get("#salt")
	require.EqualError(t, err, "keyring id prefix reserved #salt")

	err = kr.Create(keyring.NewItem("#key", nil, "", time.Now()))
	require.EqualError(t, err, "keyring id prefix reserved #key")
	err = kr.Create(keyring.NewItem("#salt", nil, "", time.Now()))
	require.EqualError(t, err, "keyring id prefix reserved #salt")
}

func TestLargeItems(t *testing.T) {
	const maxID = 254
	const maxType = 32
	const maxData = 2048

	kr, err := keyring.NewKeyring("KeysTest", keyring.SystemOrFS())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	key := bytes32(bytes.Repeat([]byte{0x01}, 32))
	err = kr.Unlock(keyring.NewKeyAuth(key))
	require.NoError(t, err)

	id := string(bytes.Repeat([]byte("a"), maxID))
	largeID := string(bytes.Repeat([]byte("a"), maxID+1))
	typ := string(bytes.Repeat([]byte("t"), maxType))
	largeType := string(bytes.Repeat([]byte("a"), maxType+1))

	large := keys.RandBytes(maxData + 1)
	err = kr.Create(keyring.NewItem(id, large, typ, time.Now()))
	require.EqualError(t, err, "keyring item value is too large")

	err = kr.Create(keyring.NewItem(largeID, []byte{0x01}, typ, time.Now()))
	require.EqualError(t, err, "keyring item value is too large")
	err = kr.Create(keyring.NewItem(id, []byte{0x01}, largeType, time.Now()))
	require.EqualError(t, err, "keyring item value is too large")

	b := bytes.Repeat([]byte{0x01}, maxData)
	err = kr.Create(keyring.NewItem(id, b, typ, time.Now()))
	require.NoError(t, err)

	item, err := kr.Get(id)
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, b, item.Data)
}

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func randKey() keyring.SecretKey {
	return keyring.SecretKey(rand32())
}

func rand32() *[32]byte {
	b := randBytes(32)
	var b32 [32]byte
	copy(b32[:], b[:32])
	return &b32
}

func bytes32(b []byte) *[32]byte {
	if len(b) != 32 {
		panic("not 32 bytes")
	}
	var b32 [32]byte
	copy(b32[:], b)
	return &b32
}
