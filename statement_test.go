package keys_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestStatement(t *testing.T) {
	clock := newClock()
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	sc := keys.NewSigchain(sk.PublicKey())
	require.Equal(t, 0, sc.Length())
	st, err := keys.GenerateStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "test", clock.Now())
	require.NoError(t, err)

	st2, err := keys.NewStatement(st.Sig, st.Data, sk.PublicKey(), st.Seq, st.Prev, st.Revoke, st.Type, st.Timestamp)
	require.NoError(t, err)
	require.Equal(t, st.Bytes(), st2.Bytes())

	rk := keys.GenerateEdX25519Key()
	_, err = keys.NewStatement(st.Sig, st.Data, rk.PublicKey(), st.Seq, st.Prev, st.Revoke, st.Type, st.Timestamp)
	require.EqualError(t, err, "verify failed")
}

func TestStatementJSON(t *testing.T) {
	clock := newClock()
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	sc := keys.NewSigchain(sk.PublicKey())
	require.Equal(t, 0, sc.Length())

	st, err := keys.GenerateStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "test", clock.Now())
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
	require.Equal(t, st.SpecificSerialization(), stOut.SpecificSerialization())

	err = sc.Add(st)
	require.NoError(t, err)

	// Revoke
	revoke, err := keys.GenerateRevoke(sc, 1, sk)
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
	require.Equal(t, revoke.SpecificSerialization(), stOut2.SpecificSerialization())
}

func TestStatementSpecificSerialization(t *testing.T) {
	clock := newClock()
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	sc := keys.NewSigchain(sk.PublicKey())
	require.Equal(t, 0, sc.Length())

	st, err := keys.GenerateStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "test", clock.Now())
	require.NoError(t, err)

	data := st.SpecificSerialization()
	expected := `{".sig":"","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","seq":1,"ts":1234567890001,"type":"test"}`
	require.Equal(t, expected, string(data))

	dataOut := st.Bytes()
	expectedOut := `{".sig":"+H4VoHKAzH8e7Fn0LTtabx1MSpmnEY7xejxzMLr13Cfu1uvj4LKDKJ8AWLP38OU+HDSqO9JYkR+MtM/o7JvzAw==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","seq":1,"ts":1234567890001,"type":"test"}`
	require.Equal(t, expectedOut, string(dataOut))

	require.Equal(t, expectedOut, string(st.Bytes()))

	stOut, err := keys.StatementFromBytes(dataOut)
	require.NoError(t, err)
	require.Equal(t, st.Data, stOut.Data)
	require.Equal(t, st.KID, stOut.KID)
	require.Equal(t, st.Seq, stOut.Seq)
	require.Equal(t, st.Prev, stOut.Prev)
	require.Equal(t, st.Revoke, stOut.Revoke)
	require.Equal(t, st.Type, stOut.Type)
	require.Equal(t, st.SpecificSerialization(), stOut.SpecificSerialization())

	_, err = keys.StatementFromBytes([]byte("{}"))
	require.EqualError(t, err, "not enough bytes for statement")

	_, err = keys.StatementFromBytes(data)
	require.EqualError(t, err, "statement bytes don't match specific serialization")

	err = sc.Add(st)
	require.NoError(t, err)

	// Revoke
	revoke, err := keys.GenerateRevoke(sc, 1, sk)
	require.NoError(t, err)

	data2 := revoke.SpecificSerialization()
	expected2 := `{".sig":"","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","prev":"V/5ecc6cFRzsi83kcaqyahjXqWp+wTxFwpJMrk+MHXA=","revoke":1,"seq":2,"type":"revoke"}`
	require.Equal(t, expected2, string(data2))

	dataOut2 := revoke.Bytes()
	expectedOut2 := `{".sig":"Ez8WFOCIjCM4SNRk6erV8t1+9tWT8Fz1lAbmxvEytV8CHwIQi3sfvrAd0JwB+oZEmMp3WC3VJMSEqkR07iS5Bw==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","prev":"V/5ecc6cFRzsi83kcaqyahjXqWp+wTxFwpJMrk+MHXA=","revoke":1,"seq":2,"type":"revoke"}`
	require.Equal(t, expectedOut2, string(dataOut2))

	require.Equal(t, expectedOut2, string(revoke.Bytes()))

	stOut2, stOutErr2 := keys.StatementFromBytes(dataOut2)
	require.NoError(t, stOutErr2)
	require.Equal(t, revoke.Data, stOut2.Data)
	require.Equal(t, revoke.KID, stOut2.KID)
	require.Equal(t, revoke.Seq, stOut2.Seq)
	require.Equal(t, revoke.Prev, stOut2.Prev)
	require.Equal(t, revoke.Revoke, stOut2.Revoke)
	require.Equal(t, revoke.Type, stOut2.Type)
	require.Equal(t, revoke.SpecificSerialization(), stOut2.SpecificSerialization())
}

func TestStatementKeyURL(t *testing.T) {
	clock := newClock()
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	sc := keys.NewSigchain(sk.PublicKey())
	require.Equal(t, 0, sc.Length())

	st, err := keys.GenerateStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "test", clock.Now())
	require.NoError(t, err)

	require.Equal(t, "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077-000000000000001", st.Key())
	require.Equal(t, "/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077/1", st.URL())
}
