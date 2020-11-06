package api_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/saltpack"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestEncryptKey(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0xef)))
	key.Notes = "some test notes"
	key.CreatedAt = clock.Now()
	key.UpdatedAt = clock.Now()

	out, err := api.EncryptKey(key, alice, bob.ID())
	require.NoError(t, err)

	dec, pk, err := api.DecryptKey(out, saltpack.NewKeyring(bob))
	require.NoError(t, err)
	require.Equal(t, alice.ID(), pk.ID())
	assert.ObjectsAreEqual(dec, key)

	_, _, err = api.DecryptKey(out, saltpack.NewKeyring())
	require.EqualError(t, err, "no decryption key found for message")
}

func TestEncryptKeyWithPassword(t *testing.T) {
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0xef)))
	key.Notes = "some test notes"
	key.CreatedAt = clock.Now()
	key.UpdatedAt = clock.Now()

	out, err := api.EncryptKeyWithPassword(key, "testpassword")
	require.NoError(t, err)

	dec, err := api.DecryptKeyWithPassword(out, "testpassword")
	require.NoError(t, err)
	assert.ObjectsAreEqual(dec, key)

	// TODO: Invalid password error
	_, err = api.DecryptKeyWithPassword(out, "invalidpassword")
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")
}

func TestKeyMarshal(t *testing.T) {
	clock := tsutil.NewTestClock()

	key := api.NewKey(keys.NewEdX25519KeyFromSeed(testSeed(0xef)))
	key.Notes = "some test notes"
	key.CreatedAt = clock.Now()
	key.UpdatedAt = clock.Now()

	b, err := msgpack.Marshal(key)
	require.NoError(t, err)
	expected := `([]uint8) (len=215 cap=388) {
 00000000  86 a2 69 64 d9 3e 6b 65  78 31 66 7a 6c 72 64 66  |..id.>kex1fzlrdf|
 00000010  79 34 77 6c 79 61 74 75  72 63 71 6b 66 71 39 32  |y4wlyaturcqkfq92|
 00000020  79 77 6a 37 6c 66 74 39  61 77 74 64 67 37 30 64  |ywj7lft9awtdg70d|
 00000030  32 79 66 74 7a 68 73 70  6d 63 34 35 71 73 76 67  |2yftzhspmc45qsvg|
 00000040  68 68 65 70 a4 64 61 74  61 c4 40 ef ef ef ef ef  |hhep.data.@.....|
 00000050  ef ef ef ef ef ef ef ef  ef ef ef ef ef ef ef ef  |................|
 00000060  ef ef ef ef ef ef ef ef  ef ef ef 48 be 36 a4 95  |...........H.6..|
 00000070  77 c9 d5 f0 78 05 92 02  a8 8e 97 be 95 97 ae 5b  |w...x..........[|
 00000080  51 e7 b5 44 4a c5 78 07  78 ad 01 a4 74 79 70 65  |Q..DJ.x.x...type|
 00000090  a8 65 64 78 32 35 35 31  39 a5 6e 6f 74 65 73 af  |.edx25519.notes.|
 000000a0  73 6f 6d 65 20 74 65 73  74 20 6e 6f 74 65 73 a9  |some test notes.|
 000000b0  63 72 65 61 74 65 64 41  74 d7 ff 00 3d 09 00 49  |createdAt...=..I|
 000000c0  96 02 d2 a9 75 70 64 61  74 65 64 41 74 d7 ff 00  |....updatedAt...|
 000000d0  7a 12 00 49 96 02 d2                              |z..I...|
}
`
	require.Equal(t, expected, spew.Sdump(b))

	b, err = json.MarshalIndent(key, "", "  ")
	require.NoError(t, err)
	expected = `{
  "id": "kex1fzlrdfy4wlyaturcqkfq92ywj7lft9awtdg70d2yftzhspmc45qsvghhep",
  "data": "7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+9IvjaklXfJ1fB4BZICqI6XvpWXrltR57VESsV4B3itAQ==",
  "type": "edx25519",
  "notes": "some test notes",
  "createdAt": "2009-02-13T23:31:30.001Z",
  "updatedAt": "2009-02-13T23:31:30.002Z"
}`
	require.Equal(t, expected, string(b))
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
