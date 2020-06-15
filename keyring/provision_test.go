package keyring_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestAuth(t *testing.T) {
	kr, err := keyring.New(keyring.Mem())
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
	err = kr.Set(item)
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
	ok, err := kr.Deprovision(provision2.ID, true)
	require.NoError(t, err)
	require.True(t, ok)

	_, err = kr.Unlock(key2)
	require.EqualError(t, err, "invalid keyring auth")

	// Test wrong password
	wrongpass, err := keyring.KeyForPassword("invalidpassword", salt)
	require.NoError(t, err)
	_, err = kr.Unlock(wrongpass)
	require.EqualError(t, err, "invalid keyring auth")
}

func TestSystemStore(t *testing.T) {
	if skipSystem(t) {
		return
	}
	kr, err := keyring.New(keyring.System("KeysTest"))
	require.NoError(t, err)
	defer func() { _ = kr.Reset() }()
	salt := bytes.Repeat([]byte{0x01}, 32)

	provision := keyring.NewProvision(keyring.UnknownAuth)
	key, err := keyring.KeyForPassword("password123", salt)
	require.NoError(t, err)
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	st := keyring.NewSystem("KeysTest")

	mk, err := st.Get("#auth-" + provision.ID)
	require.NoError(t, err)
	require.NotNil(t, mk)

	err = st.Set(".raw", []byte{0x01})
	require.NoError(t, err)

	_, err = kr.Get(".raw")
	require.EqualError(t, err, "invalid keyring auth")
}

func TestAuthV1(t *testing.T) {
	kr, err := keyring.New(keyring.Mem())
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

	ok, err := kr.Deprovision("v1.auth", true)
	require.NoError(t, err)
	require.True(t, ok)
	provisions, err = kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, 0, len(provisions))
}

func TestProvisions(t *testing.T) {
	var err error
	kr := testMem(t, true)
	key := keys.Rand32()
	id := encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Base62)
	provision := &keyring.Provision{
		ID: id,
	}
	err = kr.Provision(key, provision)
	require.NoError(t, err)

	provisions, err := kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, 1, len(provisions))
	require.Equal(t, "0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29", provisions[0].ID)
}

func TestSaveProvision(t *testing.T) {
	var err error
	kr := testMem(t, true)

	id := encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Base62)
	provision := &keyring.Provision{
		ID: id,
	}
	err = kr.SaveProvision(provision)
	require.NoError(t, err)

	provisions, err := kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, 1, len(provisions))
	require.Equal(t, "0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29", provisions[0].ID)
}

func TestProvisionMarshal(t *testing.T) {
	var err error

	clock := tsutil.NewClock()
	id := encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Base62)
	salt := bytes.Repeat([]byte{0x02}, 32)
	provision := &keyring.Provision{
		ID:        id,
		Type:      keyring.PasswordAuth,
		AAGUID:    "123",
		Salt:      salt,
		NoPin:     true,
		CreatedAt: clock.Now(),
	}
	kr := testMem(t, true)
	key := keys.Rand32()
	err = kr.Provision(key, provision)
	require.NoError(t, err)

	provisions, err := kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, 1, len(provisions))
	out := provisions[0]
	require.Equal(t, provision.ID, out.ID)
	require.Equal(t, provision.Salt, out.Salt)
	require.Equal(t, provision.AAGUID, out.AAGUID)
	require.Equal(t, provision.NoPin, out.NoPin)
	require.Equal(t, provision.Type, out.Type)
	require.Equal(t, provision.CreatedAt.UTC(), out.CreatedAt.UTC())

	b, err := msgpack.Marshal(provision)
	require.NoError(t, err)
	expected := `([]uint8) (len=134 cap=267) {
 00000000  86 a2 69 64 d9 2b 30 45  6c 36 58 46 58 77 73 55  |..id.+0El6XFXwsU|
 00000010  46 44 38 4a 32 76 47 78  73 61 62 6f 57 37 72 5a  |FD8J2vGxsaboW7rZ|
 00000020  59 6e 51 52 42 50 35 64  39 65 72 77 52 77 64 32  |YnQRBP5d9erwRwd2|
 00000030  39 a4 74 79 70 65 a8 70  61 73 73 77 6f 72 64 a3  |9.type.password.|
 00000040  63 74 73 d7 ff 00 3d 09  00 49 96 02 d2 a6 61 61  |cts...=..I....aa|
 00000050  67 75 69 64 a3 31 32 33  a4 73 61 6c 74 c4 20 02  |guid.123.salt. .|
 00000060  02 02 02 02 02 02 02 02  02 02 02 02 02 02 02 02  |................|
 00000070  02 02 02 02 02 02 02 02  02 02 02 02 02 02 02 a5  |................|
 00000080  6e 6f 70 69 6e c3                                 |nopin.|
}
`
	require.Equal(t, expected, spew.Sdump(b))
}
