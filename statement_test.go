package keys_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestStatement(t *testing.T) {
	clock := tsutil.NewTestClock()
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	st := keys.Statement{
		KID:       sk.ID(),
		Data:      bytes.Repeat([]byte{0x01}, 16),
		Type:      "test",
		Timestamp: clock.Now(),
	}
	_, err := st.Bytes()
	require.EqualError(t, err, "missing signature")

	err = st.Verify()
	require.EqualError(t, err, "missing signature")

	err = st.Sign(sk)
	require.NoError(t, err)

	b, err := st.Bytes()
	require.NoError(t, err)
	expected := `{".sig":"p4iGIBoX5nCHpTSEUCFXg9YsZDSTn5sZHAudE7j00u7RYTNxYEABPLtpW0ZW8CJqxOXube/zxqtcx3sQwwgnBw==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","ts":1234567890001,"type":"test"}`
	require.Equal(t, expected, string(b))

	bytesToSign := st.BytesToSign()
	expected = `{".sig":"","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","ts":1234567890001,"type":"test"}`
	require.Equal(t, expected, string(bytesToSign))

	err = st.Verify()
	require.NoError(t, err)

	err = st.VerifySpecific(bytesToSign)
	require.NoError(t, err)

	altered := `{".sig":"","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","ts":1234567890001,"type":"test","x":1}`
	err = st.VerifySpecific([]byte(altered))
	require.EqualError(t, err, "statement bytes failed to match specific serialization")

	st.Sig[63] = 0x00
	err = st.Verify()
	require.EqualError(t, err, "verify failed")
}

func TestSignedStatement(t *testing.T) {
	clock := tsutil.NewTestClock()
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	st := keys.Statement{
		KID:       sk.ID(),
		Data:      bytes.Repeat([]byte{0x01}, 16),
		Type:      "test",
		Timestamp: clock.Now(),
	}
	err := st.Sign(sk)
	require.NoError(t, err)
	err = st.Verify()
	require.NoError(t, err)

	rk := keys.GenerateEdX25519Key()
	st.KID = rk.ID()
	err = st.Verify()
	require.EqualError(t, err, "verify failed")
}

func TestSigchainStatement(t *testing.T) {
	clock := tsutil.NewTestClock()
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	sc := keys.NewSigchain(sk.ID())
	require.Equal(t, 0, sc.Length())
	st, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "test", clock.Now())
	require.NoError(t, err)
	err = st.Verify()
	require.NoError(t, err)

	rk := keys.GenerateEdX25519Key()
	st.KID = rk.ID()
	err = st.Verify()
	require.EqualError(t, err, "verify failed")
}

func TestStatementJSON(t *testing.T) {
	clock := tsutil.NewTestClock()
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	sc := keys.NewSigchain(sk.ID())
	require.Equal(t, 0, sc.Length())

	st, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "test", clock.Now())
	require.NoError(t, err)

	b, err := json.Marshal(st)
	require.NoError(t, err)

	var stOut keys.Statement
	err = json.Unmarshal(b, &stOut)
	require.NoError(t, err)

	require.Equal(t, st.Data, stOut.Data)
	require.Equal(t, st.KID, stOut.KID)
	require.Equal(t, st.Seq, stOut.Seq)
	require.Equal(t, st.Prev, stOut.Prev)
	require.Equal(t, st.Revoke, stOut.Revoke)
	require.Equal(t, st.Type, stOut.Type)
	require.Equal(t, st.BytesToSign(), stOut.BytesToSign())

	err = sc.Add(st)
	require.NoError(t, err)

	// Revoke
	revoke, err := keys.NewRevokeStatement(sc, 1, sk)
	require.NoError(t, err)

	b2, err := json.Marshal(revoke)
	require.NoError(t, err)

	var stOut2 keys.Statement
	err = json.Unmarshal(b2, &stOut2)
	require.NoError(t, err)

	require.Equal(t, revoke.Data, stOut2.Data)
	require.Equal(t, revoke.KID, stOut2.KID)
	require.Equal(t, revoke.Seq, stOut2.Seq)
	require.Equal(t, revoke.Prev, stOut2.Prev)
	require.Equal(t, revoke.Revoke, stOut2.Revoke)
	require.Equal(t, st.Timestamp, stOut.Timestamp)
	require.Equal(t, revoke.Type, stOut2.Type)
	require.Equal(t, revoke.BytesToSign(), stOut2.BytesToSign())
}

func TestStatementSpecificSerialization(t *testing.T) {
	clock := tsutil.NewTestClock()
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sc := keys.NewSigchain(sk.ID())
	require.Equal(t, 0, sc.Length())

	st, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "test", clock.Now())
	require.NoError(t, err)

	data := st.BytesToSign()
	expected := `{".sig":"","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","seq":1,"ts":1234567890001,"type":"test"}`
	require.Equal(t, expected, string(data))

	dataOut, err := st.Bytes()
	require.NoError(t, err)
	expectedOut := `{".sig":"+H4VoHKAzH8e7Fn0LTtabx1MSpmnEY7xejxzMLr13Cfu1uvj4LKDKJ8AWLP38OU+HDSqO9JYkR+MtM/o7JvzAw==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","seq":1,"ts":1234567890001,"type":"test"}`
	require.Equal(t, expectedOut, string(dataOut))

	b, err := st.Bytes()
	require.NoError(t, err)
	require.Equal(t, expectedOut, string(b))

	// err = keys.VerifyStatementBytes(dataOut, sk.PublicKey())
	// require.NoError(t, err)

	var stOut keys.Statement
	err = json.Unmarshal(b, &stOut)
	require.NoError(t, err)
	require.Equal(t, st.Data, stOut.Data)
	require.Equal(t, st.KID, stOut.KID)
	require.Equal(t, st.Seq, stOut.Seq)
	require.Equal(t, st.Prev, stOut.Prev)
	require.Equal(t, st.Revoke, stOut.Revoke)
	require.Equal(t, st.Type, stOut.Type)
	require.Equal(t, st.BytesToSign(), stOut.BytesToSign())

	err = sc.Add(st)
	require.NoError(t, err)

	// Revoke
	revoke, err := keys.NewRevokeStatement(sc, 1, sk)
	require.NoError(t, err)

	data2 := revoke.BytesToSign()
	expected2 := `{".sig":"","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","prev":"V/5ecc6cFRzsi83kcaqyahjXqWp+wTxFwpJMrk+MHXA=","revoke":1,"seq":2,"type":"revoke"}`
	require.Equal(t, expected2, string(data2))

	dataOut2, err := revoke.Bytes()
	require.NoError(t, err)
	expectedOut2 := `{".sig":"Ez8WFOCIjCM4SNRk6erV8t1+9tWT8Fz1lAbmxvEytV8CHwIQi3sfvrAd0JwB+oZEmMp3WC3VJMSEqkR07iS5Bw==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","prev":"V/5ecc6cFRzsi83kcaqyahjXqWp+wTxFwpJMrk+MHXA=","revoke":1,"seq":2,"type":"revoke"}`
	require.Equal(t, expectedOut2, string(dataOut2))

	rb, err := revoke.Bytes()
	require.NoError(t, err)
	require.Equal(t, expectedOut2, string(rb))

	// err = keys.VerifyStatementBytes(dataOut2, sk.PublicKey())
	// require.NoError(t, err)

	var stOut2 keys.Statement
	err = json.Unmarshal(dataOut2, &stOut2)
	require.NoError(t, err)
	require.Equal(t, revoke.Data, stOut2.Data)
	require.Equal(t, revoke.KID, stOut2.KID)
	require.Equal(t, revoke.Seq, stOut2.Seq)
	require.Equal(t, revoke.Prev, stOut2.Prev)
	require.Equal(t, revoke.Revoke, stOut2.Revoke)
	require.Equal(t, revoke.Type, stOut2.Type)
	require.Equal(t, revoke.BytesToSign(), stOut2.BytesToSign())
}
func TestBadStatements(t *testing.T) {
	var empty keys.Statement
	var err error
	err = json.Unmarshal([]byte("{}"), &empty)
	require.EqualError(t, err, "not enough bytes for statement")

	// sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	// st := &keys.Statement{
	// 	KID:  sk.ID(),
	// 	Data: []byte("test"),
	// }
	// err = st.Sign(sk)
	// require.NoError(t, err)
	// b, err := st.Bytes()
	// require.NoError(t, err)
	// fmt.Printf("signed: %s\n", string(b))

	st2 := keys.Statement{
		Sig:  encoding.MustDecode("gQXqQal1NaNnPZFdcrX5CQ/CVUsqZkxhM4s8FGX5SfPWvyfSvhyDTA4jXHOn4buti6fbn7Of4blxfiLezwudCA==", encoding.Base64),
		KID:  keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"),
		Data: []byte("test"),
	}
	err = st2.Verify()
	require.NoError(t, err)

	st3 := keys.Statement{
		Sig: encoding.MustDecode("gQXqQal1NaNnPZFdcrX5CQ/CVUsqZkxhM4s8FGX5SfPWvyfSvhyDTA4jXHOn4buti6fbn7Of4blxfiLezwudCA==", encoding.Base64),
		KID: keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"),
	}
	err = st3.Verify()
	require.EqualError(t, err, "verify failed")

	// Statement missing data
	str := `{".sig":"gQXqQal1NaNnPZFdcrX5CQ/CVUsqZkxhM4s8FGX5SfPWvyfSvhyDTA4jXHOn4buti6fbn7Of4blxfiLezwudCA==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"}`
	var out keys.Statement
	err = json.Unmarshal([]byte(str), &out)
	require.EqualError(t, err, "verify failed")

	// Statement adding data
	str2 := `{".sig":"gQXqQal1NaNnPZFdcrX5CQ/CVUsqZkxhM4s8FGX5SfPWvyfSvhyDTA4jXHOn4buti6fbn7Of4blxfiLezwudCA==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","seq":1}`
	var out2 keys.Statement
	err = json.Unmarshal([]byte(str2), &out2)
	require.EqualError(t, err, "verify failed")
}

func TestStatementKeyURL(t *testing.T) {
	clock := tsutil.NewTestClock()
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	sc := keys.NewSigchain(sk.ID())
	require.Equal(t, 0, sc.Length())

	st, err := keys.NewSigchainStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "test", clock.Now())
	require.NoError(t, err)

	require.Equal(t, "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077-000000000000001", keys.StatementID(st.KID, st.Seq))
	require.Equal(t, "/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077/1", st.URL())
}
