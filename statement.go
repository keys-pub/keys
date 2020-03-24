package keys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

// Statement signed.
type Statement struct {
	// Sig is the signature bytes.
	Sig []byte

	// Data.
	Data []byte
	// KID is the key that signed.
	KID ID

	// Seq in a sigchain (1 is root, optional if not in sigchain).
	Seq int
	// Prev is a hash of the previous item in the sigchain (optional if root).
	Prev []byte
	// Revoke refers to a previous signed seq to revoke (optional).
	Revoke int

	// Type (optional).
	Type string

	// Timestamp (optional).
	Timestamp time.Time

	// serialized the specific serialization.
	serialized []byte
}

// StatementPublicKey is public key for a Statement.
type StatementPublicKey interface {
	ID() ID
	Verify(b []byte) ([]byte, error)
	VerifyDetached(sig []byte, b []byte) error
}

// NewStatement creates a new statement from specified parameters.
// Use NewSigchainStatement for a signed Sigchain Statement.
// Use NewSignedStatement for a signed Statement outside a Sigchain.
func NewStatement(sig []byte, data []byte, spk StatementPublicKey, seq int, prev []byte, revoke int, typ string, ts time.Time) (*Statement, error) {
	st := NewUnverifiedStatement(sig, data, spk.ID(), seq, prev, revoke, typ, ts)
	if err := st.Verify(spk); err != nil {
		return nil, err
	}
	return st, nil
}

// NewUnverifiedStatement creates an unverified statement.
func NewUnverifiedStatement(sig []byte, data []byte, kid ID, seq int, prev []byte, revoke int, typ string, ts time.Time) *Statement {
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

// NewSignedStatement creates a signed Statement.
// Use NewSigchainStatement if part of a Sigchain.
func NewSignedStatement(b []byte, sk *EdX25519Key, typ string, ts time.Time) (*Statement, error) {
	st := &Statement{
		Data:      b,
		KID:       sk.ID(),
		Timestamp: ts,
		Type:      typ,
	}
	if err := signStatement(st, sk); err != nil {
		return nil, err
	}
	return st, nil
}

// Key for a Statement.
// If Seq is not set, then there is no key.
// Key looks like "kpe1a4yj333g68pvd6hfqvufqkv4vy54jfe6t33ljd3kc9rpfty8xlgsfte2sn-000000000000001".
func (s Statement) Key() string {
	return StatementKey(s.KID, s.Seq)
}

// StatementKey returns key for Statement kid,seq.
// If seq is <= 0, then there is no key.
// Path looks like "kpe1a4yj333g68pvd6hfqvufqkv4vy54jfe6t33ljd3kc9rpfty8xlgsfte2sn-000000000000001".
func StatementKey(kid ID, seq int) string {
	if seq <= 0 {
		return ""
	}
	return kid.WithSeq(seq)
}

// URL returns path string for a Statement in the HTTP API.
// If Seq is not set, then there is no path.
// Path looks like "/ed1a4yj333g68pvd6hfqvufqkv4vy54jfe6t33ljd3kc9rpfty8xlgsfte2sn/1".
func (s Statement) URL() string {
	if s.Seq == 0 {
		return ""
	}
	return "/" + s.KID.String() + "/" + fmt.Sprintf("%d", s.Seq)
}

// SpecificSerialization is the specific serialization or the bytes to sign.
// It is the statement serialized without the sig value.
func (s Statement) SpecificSerialization() []byte {
	return s.serialized
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

	st := NewUnverifiedStatement(stf.Sig, stf.Data, kid, stf.Seq, stf.Prev, stf.Revoke, stf.Type, ts)

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
func (s *Statement) Verify(spk StatementPublicKey) error {
	if spk == nil {
		return errors.Errorf("missing sigchain public key")
	}
	b := bytesJoin(s.Sig, s.serialized)
	_, err := spk.Verify(b)
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
		NewStringEntry(".sig", encoding.MustEncode(sig, encoding.Base64)),
	}
	if len(st.Data) != 0 {
		mes = append(mes, NewStringEntry("data", encoding.MustEncode(st.Data, encoding.Base64)))
	}
	mes = append(mes, NewStringEntry("kid", st.KID.String()))
	if len(st.Prev) != 0 {
		mes = append(mes, NewStringEntry("prev", encoding.MustEncode(st.Prev, encoding.Base64)))
	}
	if st.Revoke != 0 {
		mes = append(mes, NewIntEntry("revoke", st.Revoke))
	}
	if st.Seq != 0 {
		mes = append(mes, NewIntEntry("seq", st.Seq))
	}
	if !st.Timestamp.IsZero() {
		mes = append(mes, NewIntEntry("ts", int(TimeToMillis(st.Timestamp))))
	}
	if st.Type != "" {
		mes = append(mes, NewStringEntry("type", st.Type))
	}

	return Marshal(mes)
}
