package keys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSigchain(t *testing.T) {
	clock := newClock()
	alice, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	sc := NewSigchain(alice.PublicKey())
	require.Equal(t, 0, sc.Length())

	st, err := GenerateStatement(sc, bytes.Repeat([]byte{0x01}, 16), alice, "test", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	require.Equal(t, 1, sc.LastSeq())

	res := sc.FindLast("test")
	require.NotNil(t, res)
	require.Equal(t, bytes.Repeat([]byte{0x01}, 16), res.Data)
	require.Equal(t, 1, sc.Length())

	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	require.True(t, sc.IsRevoked(1))
	require.Equal(t, 2, sc.Length())
	require.Equal(t, 2, sc.LastSeq())

	res = sc.FindLast("test")
	require.Nil(t, res)

	st2, err := GenerateStatement(sc, bytes.Repeat([]byte{0x02}, 16), alice, "test", clock.Now())
	require.NoError(t, err)
	siErr2 := sc.Add(st2)
	require.NoError(t, siErr2)

	res = sc.FindLast("test")
	require.NotNil(t, res)
	require.Equal(t, bytes.Repeat([]byte{0x02}, 16), res.Data)

	st3, err := GenerateStatement(sc, bytes.Repeat([]byte{0x03}, 16), alice, "test", clock.Now())
	require.NoError(t, err)
	siErr3 := sc.Add(st3)
	require.NoError(t, siErr3)

	res = sc.FindLast("")
	require.NotNil(t, res)
	require.Equal(t, bytes.Repeat([]byte{0x03}, 16), res.Data)

	sts := sc.FindAll("test")
	require.Equal(t, 2, len(sts))

	require.Equal(t, 4, len(sc.Statements()))

	st4, err := GenerateStatement(sc, []byte{}, alice, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st4)
	require.EqualError(t, err, "no data")

	_, err = GenerateStatement(sc, []byte{}, GenerateSignKey(), "", clock.Now())
	require.EqualError(t, err, "invalid sigchain sign public key")

	// Revoke invalid seq
	_, err = sc.Revoke(0, alice)
	require.EqualError(t, err, "invalid revoke seq 0")

	// Revoke statement that doesn't exist
	_, err = sc.Revoke(10000, alice)
	require.EqualError(t, err, "invalid revoke seq 10000")

	// Revoke again
	_, err = sc.Revoke(1, alice)
	require.EqualError(t, err, "already revoked")

	// Revoke self
	_, err = sc.Revoke(5, alice)
	require.EqualError(t, err, "invalid revoke seq 5")

	spew, err := sc.Spew()
	require.NoError(t, err)
	expected := `/sigchain/ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw/1 {".sig":"RfBktB0axROlrmq0++FxK7QHXt4Aq59VOL5tJzSHHi7MdwIEwjGQusB3NqDd3HRivWD4B0unNET68UswxTvSBQ==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw","seq":1,"ts":1234567890001,"type":"test"}
/sigchain/ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw/2 {".sig":"7SzEDHKXUoEvZKicSdVx9ftBc9sdpUWlGtOCIRPDNFRM4/KWDVEoXAdcQtwxv7ccpaTDOA5GK3HkYYaAfVe6Cg==","kid":"ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw","prev":"+muAFil+RqSW0hTqfVTH+aFT4kX3+15yt5lKcnkbNhU=","revoke":1,"seq":2,"type":"revoke"}
/sigchain/ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw/3 {".sig":"PN5rJJpTSTtxU6TLHtsU01l7Q14uKidAG0jEvHheUmCT4ax6hJyar9ulMFbpWMjjilpYs3X0vul+sg8kv/abDQ==","data":"AgICAgICAgICAgICAgICAg==","kid":"ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw","prev":"OS4zWLgbHoqyO7oVRnovjuEz/qN9bfJXOIBLmNSSc3k=","seq":3,"ts":1234567890002,"type":"test"}
/sigchain/ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw/4 {".sig":"ZdJlZ+x882ABQrYazysbuPhoFGMiAujcYGo2+aDyLzCtpbaTJxPEa5msFtEcg0bqjWuNnTUmLKx8PLVvYnuBAw==","data":"AwMDAwMDAwMDAwMDAwMDAw==","kid":"ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw","prev":"tCG8UeQh4iO0oSdw7EJ5YQ63dbdMXLFN/cXmyM5v9Fg=","seq":4,"ts":1234567890003,"type":"test"}
`
	require.Equal(t, expected, spew.String())
}

func TestSigchainJSON(t *testing.T) {
	clock := newClock()
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	sc := NewSigchain(sk.PublicKey())

	st, err := GenerateStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	st0 := sc.Statements()[0]
	expectedStatement := `{".sig":"+NEHVE3zlc9AmC6uEwJF5MfAGGZcO7ZZZ1VI64ol6mXe/ZQ6fZEn9R1KWI05olHV03B9E8ofqep0d7Z2nCRHAQ==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw","seq":1,"ts":1234567890001}`
	require.Equal(t, expectedStatement, string(st0.Bytes()))

	b, err := json.Marshal(st0)
	require.NoError(t, err)
	expectedEntry := `{".sig":"+NEHVE3zlc9AmC6uEwJF5MfAGGZcO7ZZZ1VI64ol6mXe/ZQ6fZEn9R1KWI05olHV03B9E8ofqep0d7Z2nCRHAQ==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw","seq":1,"ts":1234567890001}`
	require.Equal(t, expectedEntry, string(b))

	stb, err := StatementFromBytes(b)
	require.NoError(t, err)
	bout := stb.Bytes()
	require.Equal(t, expectedEntry, string(bout))

	st2, err := GenerateStatement(sc, bytes.Repeat([]byte{0x02}, 16), sk, "", clock.Now())
	require.NoError(t, err)
	siErr2 := sc.Add(st2)
	require.NoError(t, siErr2)
	entry2 := sc.Statements()[1]
	expectedStatement2 := `{".sig":"WhR7Vg55ho+ZImJVZolp/W7chnSHlS4x8WLpjUwmWq+taGV6G6j6iHqbAKTrHx1HyvQI6j9H0TRzemHX6m+3Cg==","data":"AgICAgICAgICAgICAgICAg==","kid":"ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw","prev":"QT9kn83lDKhROP1e5hm6gbNIn87g9qB+ENAeZIYlR5c=","seq":2,"ts":1234567890002}`
	require.Equal(t, expectedStatement2, string(entry2.Bytes()))

	_, siErr3 := sc.Revoke(2, sk)
	require.NoError(t, siErr3)
	entry3 := sc.Statements()[2]
	expectedStatement3 := `{".sig":"rAE1SMgKRGI4DpZZqZY0IbXfW7ebVR3X4flFsRZxKbpGApwUjcBGEN1csAEYn4aFP5DnctCAM320BQkPvYkcBw==","kid":"ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw","prev":"RDcf+K1Hhy2f6ahA1rvaVB5Yfn5o9YB7C1k0Tg+rX/w=","revoke":2,"seq":3,"type":"revoke"}`
	require.Equal(t, expectedStatement3, string(entry3.Bytes()))
}

func TestSigchainUsers(t *testing.T) {
	clock := newClock()
	req := NewMockRequestor()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)
	alice, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	sc := NewSigchain(alice.PublicKey())
	require.Equal(t, 0, sc.Length())

	users := sc.Users()
	require.Equal(t, 0, len(users))

	user, err := NewUser(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, user, alice, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	users = sc.Users()
	require.Equal(t, 1, len(users))
	require.Equal(t, "alice", users[0].Name)
	require.Equal(t, "github", users[0].Service)
	require.Equal(t, "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", users[0].URL)
	require.Equal(t, 1, users[0].Seq)

	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	users = sc.Users()
	require.Equal(t, 0, len(users))

	user2, err := NewUser(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	st2, err := GenerateUserStatement(sc, user2, alice, clock.Now())
	require.EqualError(t, err, "user seq mismatch")

	user2, err = NewUser(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 3)
	require.NoError(t, err)
	st2, err = GenerateUserStatement(sc, user2, alice, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	users = sc.Users()
	require.Equal(t, 1, len(users))
	require.Equal(t, "alice", users[0].Name)
	require.Equal(t, "github", users[0].Service)
	require.Equal(t, "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", users[0].URL)
	require.Equal(t, 3, users[0].Seq)
}

func ExampleNewSigchain() {
	clock := newClock()
	alice := GenerateSignKey()
	sc := NewSigchain(alice.PublicKey())

	// Create root statement
	st, err := GenerateStatement(sc, []byte("hi! 🤓"), alice, "", clock.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := sc.Add(st); err != nil {
		log.Fatal(err)
	}

	// Add 2nd statement
	st2, err := GenerateStatement(sc, []byte("2nd message"), alice, "", clock.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := sc.Add(st2); err != nil {
		log.Fatal(err)
	}

	// Revoke 2nd statement
	_, err = sc.Revoke(2, alice)
	if err != nil {
		log.Fatal(err)
	}

	// Spew
	spew, err := sc.Spew()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(spew.String())
}
