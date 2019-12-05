package keys

import (
	"bytes"
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSigchain(t *testing.T) {
	clock := newClock()
	alice, err := NewSignKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)

	sc := NewSigchain(alice.PublicKey)
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
	require.EqualError(t, err, "invalid sigchain sign key")

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
	expected := `/sigchain/PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah/1 {".sig":"QZvoXDlq0iKdC08vayCtgr5yUdg2/VDb5gbrafdOUErtsk5L8vhwmSRCGtKnEbYDM9i1VScLXkXyM05bFmiwAg==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah","seq":1,"ts":1234567890001,"type":"test"}
/sigchain/PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah/2 {".sig":"heFGkRjrdk03URBk2GAZ2sGtPDKU6WTd8nrmUkd22CLe7+IfX/YaEcsjQyzJxJ/sFQ/aroe9S+Uu38xOOdVuCw==","kid":"PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah","prev":"DDnsc5J6OOQq20OYaDIzX2IUDuDMHakTWSa4PjLXbWI=","revoke":1,"seq":2,"type":"revoke"}
/sigchain/PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah/3 {".sig":"vWguJD5Z2Ob+D+m9Y3H+B55ubs18QfPj3GsIZuomo3yLx2kQBYn9RsRKUjWK6CkZUQsjlXpMOWu/ujYop/YVAw==","data":"AgICAgICAgICAgICAgICAg==","kid":"PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah","prev":"hfb6HlovgFGVSlR5X9iHlo1wK9GNDq8JuQNzeq0X0oE=","seq":3,"ts":1234567890002,"type":"test"}
/sigchain/PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah/4 {".sig":"5IGKfi9EDp0ObHr6P6AWdZlxKlcHazkrx89yWOAAYuoRnpot/+hMp6zmT244Ilp0vAYUS2jSl/qHAEq4Xa/9AA==","data":"AwMDAwMDAwMDAwMDAwMDAw==","kid":"PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah","prev":"TAkV8beRWwzt1W5XdPgb7dJIjzalmaoJKxTylfg/ntc=","seq":4,"ts":1234567890003,"type":"test"}
`
	require.Equal(t, expected, spew.String())
}

func TestSigchainJSON(t *testing.T) {
	clock := newClock()
	sk, err := NewSignKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)

	sc := NewSigchain(sk.PublicKey)

	st, err := GenerateStatement(sc, bytes.Repeat([]byte{0x01}, 16), sk, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	st0 := sc.Statements()[0]
	expectedStatement := `{".sig":"VdG/QyAxMIsKjgGWwOVdTjyeRzDzp0uaA3YD8xLbewqiAwA8lE7tRKy26mBi1/fUiDKqIlputJBDvvCySdK2DQ==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah","seq":1,"ts":1234567890001}`
	require.Equal(t, expectedStatement, string(st0.Bytes()))

	b, err := json.Marshal(st0)
	require.NoError(t, err)
	expectedEntry := `{".sig":"VdG/QyAxMIsKjgGWwOVdTjyeRzDzp0uaA3YD8xLbewqiAwA8lE7tRKy26mBi1/fUiDKqIlputJBDvvCySdK2DQ==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah","seq":1,"ts":1234567890001}`
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
	expectedStatement2 := `{".sig":"IptqT4CjkDPUGatk+Xze+47YQWsjo+F/3v9QfXtoKmdlToSh6lQNFsDeHEKvc8qG6Fi5ewJz0XOZy8aaJt8YAA==","data":"AgICAgICAgICAgICAgICAg==","kid":"PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah","prev":"JHt8UTBGWjHh/jrfZUj2NVp4c7MOdyTdUoUIqt0vwhA=","seq":2,"ts":1234567890002}`
	require.Equal(t, expectedStatement2, string(entry2.Bytes()))

	_, siErr3 := sc.Revoke(2, sk)
	require.NoError(t, siErr3)
	entry3 := sc.Statements()[2]
	expectedStatement3 := `{".sig":"hd+Yl286XevC417p7rnWjj2xXhlMBfUGeKnFWiszB8/gKECy2jFDnZJIJfs0GusWqOvzSKSV3BEdB7ECELVUCw==","kid":"PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah","prev":"h43YRzHdnFFjL+hl+7y8Tk8ikcDVcS9xkhctBrAGjZA=","revoke":2,"seq":3,"type":"revoke"}`
	require.Equal(t, expectedStatement3, string(entry3.Bytes()))
}

func ExampleNewSigchain() {
	clock := newClock()
	alice := GenerateKey()
	sc := NewSigchain(alice.PublicKey().SignPublicKey())

	// Create root statement
	st, err := GenerateStatement(sc, []byte("hi! 🤓"), alice.SignKey(), "", clock.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := sc.Add(st); err != nil {
		log.Fatal(err)
	}

	// Add 2nd statement
	st2, err := GenerateStatement(sc, []byte("2nd message"), alice.SignKey(), "", clock.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := sc.Add(st2); err != nil {
		log.Fatal(err)
	}

	// Revoke 2nd statement
	_, err = sc.Revoke(2, alice.SignKey())
	if err != nil {
		log.Fatal(err)
	}

	// spew, err := Spew(sc.EntryIterator(URLPathType), nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println(spew.String())
}
