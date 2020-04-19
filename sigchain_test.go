package keys_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/keys-pub/keys"
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

func testdataString(t *testing.T, path string) string {
	expected, err := ioutil.ReadFile(path)
	require.NoError(t, err)
	return strings.ReplaceAll(string(expected), "\r\n", "\n")
}

func TestSigchain(t *testing.T) {
	clock := newClock()
	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	sc := keys.NewSigchain(alice.ID())
	require.Equal(t, 0, sc.Length())

	st, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x01}, 16), alice, "test", clock.Now())
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

	st2, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x02}, 16), alice, "test", clock.Now())
	require.NoError(t, err)
	siErr2 := sc.Add(st2)
	require.NoError(t, siErr2)

	res = sc.FindLast("test")
	require.NotNil(t, res)
	require.Equal(t, bytes.Repeat([]byte{0x02}, 16), res.Data)

	st3, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x03}, 16), alice, "test", clock.Now())
	require.NoError(t, err)
	siErr3 := sc.Add(st3)
	require.NoError(t, siErr3)

	res = sc.FindLast("")
	require.NotNil(t, res)
	require.Equal(t, bytes.Repeat([]byte{0x03}, 16), res.Data)

	sts := sc.FindAll("test")
	require.Equal(t, 2, len(sts))

	require.Equal(t, 4, len(sc.Statements()))

	st4, err := keys.NewSigchainStatement(sc, []byte{}, alice, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st4)
	require.EqualError(t, err, "no data")

	_, err = keys.NewSigchainStatement(sc, []byte{}, keys.GenerateEdX25519Key(), "", clock.Now())
	require.EqualError(t, err, "invalid sigchain public key")

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
	require.Equal(t, testdataString(t, "testdata/sc2.spew"), spew.String())
}

func TestSigchainJSON(t *testing.T) {
	clock := newClock()
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	sc := keys.NewSigchain(sk.ID())

	st, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	st0 := sc.Statements()[0]
	expectedStatement := `{".sig":"VV7Q1B54UZ5YBEmhTYt2tQACynfAWIZpZ+5sSwT+DJsRnvA2MAGW86hTVtso4optvXW2PvO0DACTPpMsC/SSDQ==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","seq":1,"ts":1234567890001}`
	b, err := st0.Bytes()
	require.NoError(t, err)
	require.Equal(t, expectedStatement, string(b))

	b, err = json.Marshal(st0)
	require.NoError(t, err)
	require.Equal(t, expectedStatement, string(b))

	// err = keys.VerifyStatementBytes(b, sk.PublicKey())
	// require.NoError(t, err)

	var stb keys.Statement
	err = json.Unmarshal(b, &stb)
	require.NoError(t, err)
	b, err = stb.Bytes()
	require.NoError(t, err)
	require.Equal(t, expectedStatement, string(b))

	st2, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x02}, 16), sk, "", clock.Now())
	require.NoError(t, err)
	siErr2 := sc.Add(st2)
	require.NoError(t, siErr2)
	entry2 := sc.Statements()[1]
	expectedStatement2 := `{".sig":"eFHVVItCK0lwZzeeejBLdxAjqu1Fo3wFQ3U1/Q7J4HyimDp892A82jiaa8SOB+DekA3vEXkJicGkiGeuBFahDw==","data":"AgICAgICAgICAgICAgICAg==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","prev":"adAq4hsj899D6Y8T6ZnvxFG6EDtJaKcXe6Sk/D/VVLo=","seq":2,"ts":1234567890002}`
	b, err = entry2.Bytes()
	require.NoError(t, err)
	require.Equal(t, expectedStatement2, string(b))

	_, siErr3 := sc.Revoke(2, sk)
	require.NoError(t, siErr3)
	entry3 := sc.Statements()[2]
	expectedStatement3 := `{".sig":"Y63sL8+BsoU7LmiHCCw6IEadu463H9Gx6B9F/WTgRBDBoIZHB3kwIeFChvlO/HFpqkK0AmkrO5AzW9/rps8JCQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","prev":"6PT7dojypKdO8YldF00QiWqBfRBh1f1D9y9C2Qn6v/Y=","revoke":2,"seq":3,"type":"revoke"}`
	b, err = entry3.Bytes()
	require.NoError(t, err)
	require.Equal(t, expectedStatement3, string(b))
}

func ExampleNewSigchain() {
	clock := newClock()
	alice := keys.GenerateEdX25519Key()
	sc := keys.NewSigchain(alice.ID())

	// Create root statement
	st, err := keys.NewSigchainStatement(sc, []byte("hi! 🤓"), alice, "", clock.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := sc.Add(st); err != nil {
		log.Fatal(err)
	}

	// Add 2nd statement
	st2, err := keys.NewSigchainStatement(sc, []byte("2nd message"), alice, "", clock.Now())
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
