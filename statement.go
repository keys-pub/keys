package keys

import (
	"bytes"
	"fmt"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/json"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

// Statement with signature.
// Use NewSigchainStatement to create a signed Sigchain Statement.
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

	// Nonce (optional).
	Nonce []byte

	// serialized the specific serialization.
	serialized []byte
}

// StatementPublicKey is public key for a Statement.
type StatementPublicKey interface {
	ID() ID
	Verify(b []byte) ([]byte, error)
	VerifyDetached(sig []byte, b []byte) error
}

// Sign the statement.
// Returns an error if already signed.
func (s *Statement) Sign(signKey *EdX25519Key) error {
	if s.Sig != nil {
		return errors.Errorf("signature already set")
	}
	if s.KID != signKey.ID() {
		return errors.Errorf("sign failed: key id mismatch")
	}
	b, err := statementBytesToSign(s)
	if err != nil {
		return err
	}
	s.serialized = b
	s.Sig = signKey.SignDetached(s.serialized)
	return nil
}

// Key for a Statement.
// If Seq is not set, then there is no key.
// Key looks like "kex1a4yj333g68pvd6hfqvufqkv4vy54jfe6t33ljd3kc9rpfty8xlgsfte2sn-000000000000001".
func (s *Statement) Key() string {
	return StatementKey(s.KID, s.Seq)
}

// StatementKey returns key for Statement kid,seq.
// If seq is <= 0, then there is no key.
// Path looks like "kex1a4yj333g68pvd6hfqvufqkv4vy54jfe6t33ljd3kc9rpfty8xlgsfte2sn-000000000000001".
func StatementKey(kid ID, seq int) string {
	if seq <= 0 {
		return ""
	}
	return kid.WithSeq(seq)
}

// URL returns path string for a Statement in the HTTP API.
// If Seq is not set, then there is no path.
// Path looks like "/kex1a4yj333g68pvd6hfqvufqkv4vy54jfe6t33ljd3kc9rpfty8xlgsfte2sn/1".
func (s *Statement) URL() string {
	if s.Seq == 0 {
		return ""
	}
	return "/" + s.KID.String() + "/" + fmt.Sprintf("%d", s.Seq)
}

// SpecificSerialization is the specific serialization or the bytes to sign.
// It is the statement serialized without the sig value.
func (s *Statement) SpecificSerialization() []byte {
	return s.serialized
}

type statementFormat struct {
	Sig       []byte `json:".sig"`
	Data      []byte `json:"data"`
	KID       string `json:"kid"`
	Nonce     []byte `json:"nonce"`
	Prev      []byte `json:"prev"`
	Revoke    int    `json:"revoke"`
	Seq       int    `json:"seq"`
	Timestamp int64  `json:"ts"`
	Type      string `json:"type"`
}

// // VerifyStatementBytes verifies statement bytes for a key.
// func VerifyStatementBytes(b []byte, spk StatementPublicKey) error {
// 	if len(b) < 97 {
// 		return errors.Errorf("not enough bytes for statement")
// 	}
// 	// It is important to verify the bytes match the specific serialization.
// 	// https://latacora.micro.blog/2019/07/24/how-not-to.html
// 	sig, err := encoding.Decode(string(b[9:97]), encoding.Base64)
// 	if err != nil {
// 		return errors.Errorf("sig value is invalid")
// 	}
// 	serialized := bytesJoin(b[0:9], b[97:])
// 	if err := spk.VerifyDetached(sig, serialized); err != nil {
// 		return err
// 	}
// 	return nil
// }

// Verify statement.
func (s *Statement) Verify() error {
	spk, err := StatementPublicKeyFromID(s.KID)
	if err != nil {
		return err
	}
	if err := spk.VerifyDetached(s.Sig, s.serialized); err != nil {
		return err
	}
	return nil
}

// MarshalJSON marshals statement to JSON.
func (s *Statement) MarshalJSON() ([]byte, error) {
	return s.Bytes()
}

// UnmarshalJSON unmarshals a statement from JSON.
func (s *Statement) UnmarshalJSON(b []byte) error {
	st, err := unmarshalJSON(b)
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
	s.Nonce = st.Nonce
	s.serialized = st.serialized
	return nil
}

// Bytes is the serialized Statement.
func (s *Statement) Bytes() ([]byte, error) {
	out, err := statementBytes(s, s.Sig)
	if err != nil {
		return nil, err
	}
	expected := bytesJoin(out[0:9], out[97:])
	if !bytes.Equal(expected, s.serialized) {
		panic(errors.Errorf("statement bytes don't match specific serialization %s != %s", string(expected), string(s.serialized)))
	}

	return out, nil
}

func statementBytesToSign(st *Statement) ([]byte, error) {
	return statementBytes(st, nil)
}

func statementBytes(st *Statement, sig []byte) ([]byte, error) {
	mes := []encoding.TextMarshaler{
		json.String(".sig", encoding.MustEncode(sig, encoding.Base64)),
	}
	if len(st.Data) != 0 {
		mes = append(mes, json.String("data", encoding.MustEncode(st.Data, encoding.Base64)))
	}
	mes = append(mes, json.String("kid", st.KID.String()))
	if len(st.Nonce) != 0 {
		mes = append(mes, json.String("nonce", encoding.MustEncode(st.Nonce, encoding.Base64)))
	}
	if len(st.Prev) != 0 {
		mes = append(mes, json.String("prev", encoding.MustEncode(st.Prev, encoding.Base64)))
	}
	if st.Revoke != 0 {
		mes = append(mes, json.Int("revoke", st.Revoke))
	}
	if st.Seq != 0 {
		mes = append(mes, json.Int("seq", st.Seq))
	}
	if !st.Timestamp.IsZero() {
		mes = append(mes, json.Int("ts", int(tsutil.Millis(st.Timestamp))))
	}
	if st.Type != "" {
		mes = append(mes, json.String("type", st.Type))
	}

	return json.Marshal(mes...)
}

// unmarshalJSON returns a Statement from JSON bytes.
func unmarshalJSON(b []byte) (*Statement, error) {
	if len(b) < 97 {
		return nil, errors.Errorf("not enough bytes for statement")
	}

	sig := b[9:97]
	bytesToSign := bytesJoin(b[0:9], b[97:])
	sigBytes, err := encoding.Decode(string(sig), encoding.Base64)
	if err != nil {
		return nil, err
	}

	var stf statementFormat
	if err := json.Unmarshal(bytesToSign, &stf); err != nil {
		return nil, errors.Errorf("statement not valid JSON")
	}
	kid, err := ParseID(stf.KID)
	if err != nil {
		return nil, err
	}
	ts := tsutil.ConvertMillis(stf.Timestamp)

	st := &Statement{
		Sig:       sigBytes,
		Data:      stf.Data,
		KID:       kid,
		Nonce:     stf.Nonce,
		Prev:      stf.Prev,
		Revoke:    stf.Revoke,
		Seq:       stf.Seq,
		Timestamp: ts,
		Type:      stf.Type,
	}
	serialized, err := statementBytesToSign(st)
	if err != nil {
		return nil, err
	}
	st.serialized = serialized

	// It is important to verify the original bytes match the specific
	// serialization.
	// We want to verify the bytes we get before unmarshalling match the same
	// bytes used to sign/verify after marshalling.
	// https://latacora.micro.blog/2019/07/24/how-not-to.html
	if !bytes.Equal(bytesToSign, st.serialized) {
		return nil, errors.Errorf("statement bytes don't match specific serialization")
	}

	if err := st.Verify(); err != nil {
		return nil, err
	}

	return st, nil
}
