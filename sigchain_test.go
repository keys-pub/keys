package keys_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func testdata(t *testing.T, path string) []byte {
	b, err := ioutil.ReadFile(path)
	require.NoError(t, err)
	b = bytes.ReplaceAll(b, []byte{'\r'}, []byte{})
	return b
}

func TestSigchain(t *testing.T) {
	clock := tsutil.NewTestClock()
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

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
	err = sc.Add(st2)
	require.NoError(t, err)

	res = sc.FindLast("test")
	require.NotNil(t, res)
	require.Equal(t, bytes.Repeat([]byte{0x02}, 16), res.Data)

	st3, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x03}, 16), alice, "test", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st3)
	require.NoError(t, err)

	res = sc.FindLast("")
	require.NotNil(t, res)
	require.Equal(t, bytes.Repeat([]byte{0x03}, 16), res.Data)

	sts := sc.FindAll("test")
	require.Equal(t, 2, len(sts))

	require.Equal(t, 4, len(sc.Statements()))

	// No data
	stNoData, err := keys.NewSigchainStatement(sc, []byte{}, alice, "test", clock.Now())
	require.NoError(t, err)
	err = sc.Add(stNoData)
	require.EqualError(t, err, "no data")

	// Missing prev
	stNoPrev := &keys.Statement{
		KID:       alice.ID(),
		Data:      []byte("test"),
		Type:      "test",
		Timestamp: clock.Now(),
		Seq:       5,
	}
	err = stNoPrev.Sign(alice)
	require.NoError(t, err)
	err = sc.Add(stNoPrev)
	require.EqualError(t, err, "invalid statement previous empty")

	// Invalid prev
	stInvalidPrev := &keys.Statement{
		KID:       alice.ID(),
		Data:      []byte("test"),
		Type:      "test",
		Timestamp: clock.Now(),
		Seq:       5,
		Prev:      bytes.Repeat([]byte{0x01}, 16),
	}
	err = stInvalidPrev.Sign(alice)
	require.NoError(t, err)
	err = sc.Add(stInvalidPrev)
	require.EqualError(t, err, "invalid statement previous, expected &3e2557533edde73ec319c34994eabf7dffc419eba1aad8d152a1e83f7eae2c8d, got 01010101010101010101010101010101")

	// Invalid seq
	prev, _ := hex.DecodeString("3e2557533edde73ec319c34994eabf7dffc419eba1aad8d152a1e83f7eae2c8d")
	stInvalidSeq := &keys.Statement{
		KID:       alice.ID(),
		Data:      []byte("test"),
		Type:      "test",
		Timestamp: clock.Now(),
		Seq:       6,
		Prev:      prev,
	}
	err = stInvalidSeq.Sign(alice)
	require.NoError(t, err)
	err = sc.Add(stInvalidSeq)
	require.EqualError(t, err, "invalid statement sequence expected 5, got 6")

	// Invalid public key
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

	spew := sc.Spew()
	require.Equal(t, string(testdata(t, "testdata/sc2.spew")), spew.String())
}

func TestSigchainJSON(t *testing.T) {
	clock := tsutil.NewTestClock()
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	sc := keys.NewSigchain(sk.ID())

	st, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	// Bytes
	st1 := sc.Statements()[0]
	st1JSON := `{".sig":"VV7Q1B54UZ5YBEmhTYt2tQACynfAWIZpZ+5sSwT+DJsRnvA2MAGW86hTVtso4optvXW2PvO0DACTPpMsC/SSDQ==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","seq":1,"ts":1234567890001}`
	b, err := st1.Bytes()
	require.NoError(t, err)
	require.Equal(t, st1JSON, string(b))

	// Marshal
	b, err = json.Marshal(st)
	require.NoError(t, err)
	require.Equal(t, st1JSON, string(b))

	// Unmarshal
	var stOut keys.Statement
	err = json.Unmarshal(b, &stOut)
	require.NoError(t, err)
	b, err = stOut.Bytes()
	require.NoError(t, err)
	require.Equal(t, st1JSON, string(b))

	// Statement #2
	st2, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x02}, 16), sk, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)
	st2JSON := `{".sig":"eFHVVItCK0lwZzeeejBLdxAjqu1Fo3wFQ3U1/Q7J4HyimDp892A82jiaa8SOB+DekA3vEXkJicGkiGeuBFahDw==","data":"AgICAgICAgICAgICAgICAg==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","prev":"adAq4hsj899D6Y8T6ZnvxFG6EDtJaKcXe6Sk/D/VVLo=","seq":2,"ts":1234567890002}`
	b, err = sc.Statements()[1].Bytes()
	require.NoError(t, err)
	require.Equal(t, st2JSON, string(b))

	// Statement #3 (revoke)
	_, err = sc.Revoke(2, sk)
	require.NoError(t, err)
	st3JSON := `{".sig":"Y63sL8+BsoU7LmiHCCw6IEadu463H9Gx6B9F/WTgRBDBoIZHB3kwIeFChvlO/HFpqkK0AmkrO5AzW9/rps8JCQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","prev":"6PT7dojypKdO8YldF00QiWqBfRBh1f1D9y9C2Qn6v/Y=","revoke":2,"seq":3,"type":"revoke"}`
	b, err = sc.Statements()[2].Bytes()
	require.NoError(t, err)
	require.Equal(t, st3JSON, string(b))

	// Unmarshal Statement array
	scJSON := "[" + st1JSON + "," + st2JSON + "," + st3JSON + "]"
	var sts []*keys.Statement
	err = json.Unmarshal([]byte(scJSON), &sts)
	require.NoError(t, err)
	sc2 := keys.NewSigchain(sk.ID())
	err = sc2.AddAll(sts)
	require.NoError(t, err)
	require.Equal(t, sc.Statements(), sc2.Statements())
}

func ExampleNewSigchain() {
	clock := tsutil.NewTestClock()
	alice := keys.GenerateEdX25519Key()
	sc := keys.NewSigchain(alice.ID())

	// Create root statement
	st, err := keys.NewSigchainStatement(sc, []byte("hi! 🤓"), alice, "example", clock.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := sc.Add(st); err != nil {
		log.Fatal(err)
	}

	// Add 2nd statement
	st2, err := keys.NewSigchainStatement(sc, []byte("2nd message"), alice, "example", clock.Now())
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
	spew := sc.Spew()
	log.Println(spew.String())

	// Output:
	//
}
