package keyring_test

import (
	"bytes"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestProvision(t *testing.T) {
	var err error

	kr := keyring.NewMem(true)
	key := keys.Rand32()
	id := encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Base62)
	provision := &keyring.Provision{
		ID: id,
	}
	err = kr.Provision(key, provision)
	require.NoError(t, err)

	provisions, err := kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, 2, len(provisions))
	require.Equal(t, "0El6XFXwsUFD8J2vGxsaboW7rZYnQRBP5d9erwRwd29", provisions[0].ID)
	require.Equal(t, "yhjskwdA6OZ1AL1YmHWZWm8LLG7HjnuCA2j5rOw8Xp1", provisions[1].ID)
}

func TestSaveProvision(t *testing.T) {
	var err error

	kr := keyring.NewMem(false)
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
	kr := keyring.NewMem(true)
	key := keys.Rand32()
	err = kr.Provision(key, provision)
	require.NoError(t, err)

	provisions, err := kr.Provisions()
	require.NoError(t, err)
	require.Equal(t, 2, len(provisions))
	require.Equal(t, "yhjskwdA6OZ1AL1YmHWZWm8LLG7HjnuCA2j5rOw8Xp1", provisions[0].ID)
	out := provisions[1]
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
