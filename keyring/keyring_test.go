package keyring_test

import (
	"bytes"
	"crypto/rand"
	"runtime"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestKeyring(t *testing.T) {
	if skipSystem(t) {
		return
	}
	// keyring.SetLogger(keyring.NewLogger(keyring.DebugLevel))
	kr, err := keyring.New(keyring.System("KeysTest"))
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	testKeyring(t, kr)
}

func testKeyring(t *testing.T, kr *keyring.Keyring) {
	salt := bytes.Repeat([]byte{0x01}, 32)
	key, err := keyring.KeyForPassword("password123", salt)
	require.NoError(t, err)

	provision := keyring.NewProvision(keyring.UnknownAuth)
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	// List
	items, err := kr.List()
	require.NoError(t, err)
	require.Equal(t, 0, len(items))

	out, err := kr.Get("abc")
	require.NoError(t, err)
	require.Nil(t, out)

	now := time.Now()

	item := keyring.NewItem("abc", []byte("password"), "type1", now)
	err = kr.Set(item)
	require.NoError(t, err)

	out, err = kr.Get("abc")
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, "abc", out.ID)
	require.Equal(t, []byte("password"), out.Data)
	require.Equal(t, tsutil.Millis(now), tsutil.Millis(out.CreatedAt))

	has, err := kr.Exists("abc")
	require.NoError(t, err)
	require.True(t, has)

	has2, err := kr.Exists("xyz")
	require.NoError(t, err)
	require.False(t, has2)

	// Update
	item.Data = []byte("newpassword")
	err = kr.Set(item)
	require.NoError(t, err)

	out, err = kr.Get("abc")
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, "abc", out.ID)
	require.Equal(t, []byte("newpassword"), out.Data)
	require.Equal(t, tsutil.Millis(now), tsutil.Millis(out.CreatedAt))

	// Create "xyz"
	err = kr.Set(keyring.NewItem("xyz", []byte("xpassword"), "type2", time.Now()))
	require.NoError(t, err)

	// List
	items, err = kr.List()
	require.NoError(t, err)
	require.Equal(t, 2, len(items))
	require.Equal(t, items[0].ID, "abc")
	require.Equal(t, items[1].ID, "xyz")

	items2, err := kr.List(keyring.WithTypes("type2"))
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
	if skipSystem(t) {
		return
	}
	kr, err := keyring.New(keyring.System("KeysTest"))
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	testReset(t, kr)
}

func testReset(t *testing.T, kr *keyring.Keyring) {
	salt := bytes.Repeat([]byte{0x01}, 32)
	provision := keyring.NewProvision(keyring.UnknownAuth)
	key, err := keyring.KeyForPassword("password123", salt)
	require.NoError(t, err)

	err = kr.Setup(key, provision)
	require.NoError(t, err)

	err = kr.Set(keyring.NewItem("key1", []byte("password"), "", time.Now()))
	require.NoError(t, err)

	salt, err = kr.Salt()
	require.NoError(t, err)

	salt2, err := kr.Salt()
	require.NoError(t, err)
	require.Equal(t, salt, salt2)

	reerr := kr.Reset()
	require.NoError(t, reerr)

	err = kr.Set(keyring.NewItem("key1", []byte("password"), "", time.Now()))
	require.EqualError(t, err, "keyring is locked")

	status, err := kr.Status()
	require.NoError(t, err)
	require.Equal(t, keyring.Setup, status)

	salt3, err := kr.Salt()
	require.NoError(t, err)
	require.NotEqual(t, salt, salt3)

	provision2 := keyring.NewProvision(keyring.UnknownAuth)
	key2, err := keyring.KeyForPassword("newpassword123", salt)
	require.NoError(t, err)
	err = kr.Setup(key2, provision2)
	require.NoError(t, err)

	require.NotEqual(t, key, key2)
}

func TestSetupUnlock(t *testing.T) {
	if skipSystem(t) {
		return
	}
	kr, err := keyring.New(keyring.System("KeysTest"))
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	testSetupUnlock(t, kr)
}

func testSetupUnlock(t *testing.T, kr *keyring.Keyring) {
	err := kr.Set(keyring.NewItem("key1", []byte("password"), "", time.Now()))
	require.EqualError(t, err, "keyring is locked")

	_, err = kr.Get("key1")
	require.EqualError(t, err, "keyring is locked")

	_, err = kr.List()
	require.EqualError(t, err, "keyring is locked")

	key := bytes32(bytes.Repeat([]byte{0x01}, 32))
	provision := keyring.NewProvision(keyring.UnknownAuth)
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	err = kr.Set(keyring.NewItem("key1", []byte("password"), "", time.Now()))
	require.NoError(t, err)

	err = kr.Lock()
	require.NoError(t, err)

	_, err = kr.List()
	require.EqualError(t, err, "keyring is locked")

	ok, err := kr.Exists("key1")
	require.NoError(t, err)
	require.True(t, ok)

	del, err := kr.Delete("key1")
	require.NoError(t, err)
	require.True(t, del)

	key2 := bytes32(bytes.Repeat([]byte{0x02}, 32))
	_, err = kr.Unlock(key2)
	require.EqualError(t, err, "invalid keyring auth")
}

func TestSetErrors(t *testing.T) {
	kr, err := keyring.New(keyring.Mem())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	key := bytes32(bytes.Repeat([]byte{0x01}, 32))
	provision := keyring.NewProvision(keyring.UnknownAuth)
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	err = kr.Set(keyring.NewItem("", nil, "", time.Time{}))
	require.EqualError(t, err, "empty id")
}

func skipSystem(t *testing.T) bool {
	if runtime.GOOS == "linux" {
		if err := keyring.CheckSystem(); err != nil {
			t.Skip()
			return true
		}
	}
	return false
}

func TestLargeItems(t *testing.T) {
	const maxID = 254
	const maxType = 32
	const maxData = 2048

	kr, err := keyring.New(keyring.Mem())
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	key := bytes32(bytes.Repeat([]byte{0x01}, 32))
	provision := keyring.NewProvision(keyring.UnknownAuth)
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	id := string(bytes.Repeat([]byte("a"), maxID))
	largeID := string(bytes.Repeat([]byte("a"), maxID+1))
	typ := string(bytes.Repeat([]byte("t"), maxType))
	largeType := string(bytes.Repeat([]byte("a"), maxType+1))

	large := keys.RandBytes(maxData + 1)
	err = kr.Set(keyring.NewItem(id, large, typ, time.Now()))
	require.EqualError(t, err, "keyring item value is too large")

	err = kr.Set(keyring.NewItem(largeID, []byte{0x01}, typ, time.Now()))
	require.EqualError(t, err, "keyring item value is too large")
	err = kr.Set(keyring.NewItem(id, []byte{0x01}, largeType, time.Now()))
	require.EqualError(t, err, "keyring item value is too large")

	b := bytes.Repeat([]byte{0x01}, maxData)
	err = kr.Set(keyring.NewItem(id, b, typ, time.Now()))
	require.NoError(t, err)

	item, err := kr.Get(id)
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, b, item.Data)
}

func TestIDs(t *testing.T) {
	if skipSystem(t) {
		return
	}

	kr, err := keyring.New(keyring.System("KeysTest"))
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()

	testIDs(t, kr)
}

func testIDs(t *testing.T, kr *keyring.Keyring) {
	var err error

	// Store set reserved
	err = kr.Store().Set("#test", []byte{0x01})
	require.NoError(t, err)

	ids, err := kr.IDs(keyring.Reserved())
	require.NoError(t, err)
	require.Equal(t, 1, len(ids))
	require.Equal(t, "#test", ids[0])

	// Setup
	salt := bytes.Repeat([]byte{0x01}, 32)
	key, err := keyring.KeyForPassword("password123", salt)
	require.NoError(t, err)
	provision := keyring.NewProvision(keyring.UnknownAuth)
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	// Create item
	item := keyring.NewItem("testid1", []byte("testpassword"), "", time.Now())
	err = kr.Set(item)
	require.NoError(t, err)

	// Lock
	err = kr.Lock()
	require.NoError(t, err)

	ids, err = kr.IDs(keyring.Reserved())
	require.NoError(t, err)
	require.Equal(t, []string{"#auth-" + provision.ID, "#provision-" + provision.ID, "#test", "testid1"}, ids)

	ids, err = kr.IDs()
	require.NoError(t, err)
	require.Equal(t, []string{"testid1"}, ids)

	ids, err = kr.IDs(keyring.WithReservedPrefix("auth"))
	require.NoError(t, err)
	require.Equal(t, []string{"#auth-" + provision.ID}, ids)

	ids, err = kr.IDs(keyring.WithReservedPrefix("#auth"))
	require.NoError(t, err)
	require.Equal(t, []string{"#auth-" + provision.ID}, ids)

	// Unlock
	_, err = kr.Unlock(key)
	require.NoError(t, err)
	provision2 := keyring.NewProvision(keyring.UnknownAuth)
	key2 := keys.Rand32()
	err = kr.Provision(key2, provision2)
	require.NoError(t, err)

	// Lock
	err = kr.Lock()
	require.NoError(t, err)

	ok, err := kr.Deprovision(provision.ID, false)
	require.NoError(t, err)
	require.True(t, ok)

	ids, err = kr.IDs(keyring.Reserved())
	require.NoError(t, err)
	require.Equal(t, []string{"#auth-" + provision2.ID, "#provision-" + provision2.ID, "#test", "testid1"}, ids)

	// Don't deprovision last
	_, err = kr.Deprovision(provision2.ID, false)
	require.EqualError(t, err, "deprovisioning the last auth is not supported")

	ok, err = kr.Deprovision(provision2.ID, true)
	require.NoError(t, err)
	require.True(t, ok)

	ids, err = kr.IDs(keyring.Reserved())
	require.NoError(t, err)
	require.Equal(t, []string{"#test", "testid1"}, ids)
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
