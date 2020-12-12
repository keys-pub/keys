package keys_test

import (
	"encoding/hex"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestID(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sid := keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077")
	require.Equal(t, sid, sk.ID())
	require.Equal(t, sk.Public(), sid.Public())
	require.Equal(t, keys.KeyType("edx25519"), sid.Type())

	bk := keys.NewX25519KeyFromSeed(testSeed(0x01))
	bid := keys.ID("kbx15nsf9y4k28p83wth93tf7hafhvfajp45d2mge80ems45gz0c5gys57cytk")
	require.Equal(t, bid, bk.ID())
	require.Equal(t, bk.Public(), bid.Public())
	require.Equal(t, keys.KeyType("x25519"), bid.Type())
}

func TestIDErrors(t *testing.T) {
	var err error

	_, err = keys.ParseID("")
	require.EqualError(t, err, "failed to parse id: empty string")

	_, err = keys.ParseID("???")
	require.EqualError(t, err, "failed to parse id: separator '1' at invalid position: pos=-1, len=3")
}

func TestIDUUID(t *testing.T) {
	id := keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077")
	require.Equal(t, "34750f98bd59fcfc946da45aaabe933b", hex.EncodeToString(id.UUID()[:]))
}

func TestIDSet(t *testing.T) {
	s := keys.NewIDSet(keys.ID("a"), keys.ID("b"), keys.ID("c"))
	require.True(t, s.Contains(keys.ID("a")))
	require.False(t, s.Contains(keys.ID("z")))
	s.Add("z")
	require.True(t, s.Contains(keys.ID("z")))
	s.Add("z")
	require.Equal(t, 4, s.Size())
	s.AddAll([]keys.ID{"m", "n"})

	expected := []keys.ID{keys.ID("a"), keys.ID("b"), keys.ID("c"), keys.ID("z"), keys.ID("m"), keys.ID("n")}
	require.Equal(t, expected, s.IDs())

	s.Clear()
	require.False(t, s.Contains(keys.ID("a")))
	require.False(t, s.Contains(keys.ID("z")))
	require.Equal(t, 0, s.Size())
}
