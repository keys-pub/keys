package keys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

// Statement in a Sigchain.
type Statement struct {
	// Sig is the signature bytes.
	Sig []byte

	// Data.
	Data []byte
	// KID is the key that signed.
	KID ID

	// Seq in a sigchain (1 is root).
	Seq int
	// Prev is a hash of the previous item in the sigchain.
	Prev []byte
	// Revoke refers to a previous signed seq to revoke.
	Revoke int

	// Type (optional).
	Type string

	// Timestamp (optional).
	Timestamp time.Time

	// serialized the specific serialization.
	serialized []byte
}

// NewStatement creates a new statement from specified parameters.
// Use GenerateStatement for an easier construction.
func NewStatement(sig []byte, data []byte, kid ID, seq int, prev []byte, revoke int, typ string, ts time.Time) (*Statement, error) {
	st := newStatement(sig, data, kid, seq, prev, revoke, typ, ts)
	if err := st.Verify(); err != nil {
		return nil, err
	}
	return st, nil
}

func newStatement(sig []byte, data []byte, kid ID, seq int, prev []byte, revoke int, typ string, ts time.Time) *Statement {
	st := &Statement{
		Sig:       sig,
		Data:      data,
		KID:       kid,
		Seq:       seq,
		Prev:      prev,
		Revoke:    revoke,
		Timestamp: ts,
		Type:      typ,
	}
	st.serialized = statementBytesToSign(st)
	return st
}

// Key for a Statement.
// If Seq is not set, then there is no key.
// Key looks like "PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah-000000000000001".
func (s Statement) Key() string {
	return StatementKey(s.KID, s.Seq)
}

// StatementKey returns key for Statement kid,seq.
// If seq is <= 0, then there is no key.
// Path looks like "PbS3oWv4b6mmCwsAQ9dguCA4gU4MwfTStUQVj8hGrtah-000000000000001".
func StatementKey(kid ID, seq int) string {
	if seq <= 0 {
		return ""
	}
	return kid.WithSeq(seq)
}

// URL returns path string for a Statement in the HTTP API.
// If Seq is not set, then there is no path.
// Path looks like "QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st/1".
func (s Statement) URL() string {
	if s.Seq == 0 {
		return ""
	}
	return s.KID.String() + "/" + fmt.Sprintf("%d", s.Seq)
}

type statementFormat struct {
	Sig       []byte `json:".sig"`
	Data      []byte `json:"data"`
	KID       string `json:"kid"`
	Prev      []byte `json:"prev"`
	Revoke    int    `json:"revoke"`
	Seq       int    `json:"seq"`
	Timestamp int    `json:"ts"`
	Type      string `json:"type"`
}

// StatementFromBytes returns Statement from JSON bytes.
func StatementFromBytes(b []byte) (*Statement, error) {
	if len(b) < 100 {
		return nil, errors.Errorf("not enough bytes for statement")
	}
	if !bytes.Equal([]byte(`{".sig":"`), b[0:9]) {
		logger.Errorf("Statement bytes don't include signature: %s", spew.Sdump(b))
		return nil, errors.Errorf("statement bytes don't include sig")
	}

	var stf statementFormat
	if err := json.Unmarshal(b, &stf); err != nil {
		return nil, err
	}
	kid, err := ParseID(stf.KID)
	if err != nil {
		return nil, err
	}
	ts := TimeFromMillis(TimeMs(stf.Timestamp))

	st := newStatement(stf.Sig, stf.Data, kid, stf.Seq, stf.Prev, stf.Revoke, stf.Type, ts)

	// It is important to verify the original bytes match the specific
	// serialization.
	// https://latacora.micro.blog/2019/07/24/how-not-to.html
	expected := bytesJoin(b[0:9], b[97:])
	if !bytes.Equal(expected, st.serialized) {
		return nil, errors.Errorf("statement bytes don't match specific serialization")
	}

	return st, nil
}

// Verify statement.
func (s *Statement) Verify() error {
	spk, err := DecodeSignPublicKey(s.KID.String())
	if err != nil {
		return err
	}
	b := bytesJoin(s.Sig, s.serialized)
	_, err = Verify(b, spk)
	if err != nil {
		return err
	}
	return nil
}

// MarshalJSON marshals statement to JSON.
func (s Statement) MarshalJSON() ([]byte, error) {
	return s.Bytes(), nil
}

// UnmarshalJSON unmarshals a statement from JSON.
func (s *Statement) UnmarshalJSON(b []byte) error {
	st, err := StatementFromBytes(b)
	if err != nil {
		return err
	}
	s.Sig = st.Sig
	s.Data = st.Data
	s.KID = st.KID
	s.Seq = st.Seq
	s.Prev = st.Prev
	s.Revoke = st.Revoke
	s.Timestamp = st.Timestamp
	s.Type = st.Type
	s.serialized = st.serialized
	return nil
}

// Bytes is the serialized Statement.
func (s *Statement) Bytes() []byte {
	out := statementBytes(s, s.Sig)
	expected := bytesJoin(out[0:9], out[97:])
	if !bytes.Equal(expected, s.serialized) {
		panic(errors.Errorf("statement bytes don't match specific serialization %s != %s", string(expected), string(s.serialized)))
	}

	return out
}

func statementBytesToSign(st *Statement) []byte {
	return statementBytes(st, nil)
}

func statementBytes(st *Statement, sig []byte) []byte {
	mes := []MarshalValue{
		NewStringEntry(".sig", MustEncode(sig, Base64)),
	}
	if len(st.Data) != 0 {
		mes = append(mes, NewStringEntry("data", MustEncode(st.Data, Base64)))
	}
	mes = append(mes, NewStringEntry("kid", st.KID.String()))
	if len(st.Prev) != 0 {
		mes = append(mes, NewStringEntry("prev", MustEncode(st.Prev, Base64)))
	}
	if st.Revoke != 0 {
		mes = append(mes, NewIntEntry("revoke", st.Revoke))
	}
	mes = append(mes, NewIntEntry("seq", st.Seq))
	if !st.Timestamp.IsZero() {
		mes = append(mes, NewIntEntry("ts", int(TimeToMillis(st.Timestamp))))
	}
	if st.Type != "" {
		mes = append(mes, NewStringEntry("type", st.Type))
	}

	return Marshal(mes)
}
