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
}

// StatementPublicKey describes a public key for a Statement.
type StatementPublicKey interface {
	ID() ID
	Verify(b []byte) ([]byte, error)
	VerifyDetached(sig []byte, b []byte) error
}

// StatementPublicKeyFromID converts ID to StatementPublicKey.
// TODO: Support other key types.
func StatementPublicKeyFromID(id ID) (StatementPublicKey, error) {
	return NewEdX25519PublicKeyFromID(id)
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
	b := s.BytesToSign()
	s.Sig = signKey.SignDetached(b)
	return nil
}

// StatementID returns and identifier for a Statement as kid-seq.
// If seq is <= 0, returns kid.
// The idenfifier looks like "kex1a4yj333g68pvd6hfqvufqkv4vy54jfe6t33ljd3kc9rpfty8xlgsfte2sn-000000000000001".
func StatementID(kid ID, seq int) string {
	if seq <= 0 {
		return kid.String()
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

// Verify statement.
// If you have the original bytes use VerifySpecific.
func (s *Statement) Verify() error {
	spk, err := StatementPublicKeyFromID(s.KID)
	if err != nil {
		return err
	}
	if len(s.Sig) == 0 {
		return errors.Errorf("missing signature")
	}
	b := s.BytesToSign()
	if err := spk.VerifyDetached(s.Sig, b); err != nil {
		return err
	}
	return nil
}

// VerifySpecific and check that bytesToSign match the statement's
// BytesToSign, to verify the original bytes match the specific
// serialization.
func (s *Statement) VerifySpecific(bytesToSign []byte) error {
	serialized := s.BytesToSign()
	// We want to verify the bytes we get before unmarshalling match the same
	// bytes used to sign/verify after marshalling.
	// https://latacora.micro.blog/2019/07/24/how-not-to.html
	if !bytes.Equal(bytesToSign, serialized) {
		return errors.Errorf("statement bytes failed to match specific serialization")
	}

	return s.Verify()
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
	return nil
}

// Bytes is the serialized Statement.
func (s *Statement) Bytes() ([]byte, error) {
	if err := s.Verify(); err != nil {
		return nil, err
	}
	return statementBytes(s, s.Sig), nil
}

// BytesToSign returns bytes to sign.
func (s *Statement) BytesToSign() []byte {
	return statementBytes(s, nil)
}

func statementBytes(st *Statement, sig []byte) []byte {
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

	b, err := json.Marshal(mes...)
	if err != nil {
		panic(err)
	}
	return b
}

// unmarshalJSON returns a Statement from JSON bytes.
func unmarshalJSON(b []byte) (*Statement, error) {
	if len(b) < 97 {
		return nil, errors.Errorf("not enough bytes for statement")
	}

	// Extract sig directly from bytes.
	sig := b[9:97]
	bytesToSign := bytesJoin(b[0:9], b[97:])
	sigBytes, err := encoding.Decode(string(sig), encoding.Base64)
	if err != nil {
		return nil, err
	}

	var stf statementFormat
	if err := json.Unmarshal(b, &stf); err != nil {
		return nil, errors.Errorf("statement not valid JSON")
	}
	kid, err := ParseID(stf.KID)
	if err != nil {
		return nil, err
	}
	ts := tsutil.ConvertMillis(stf.Timestamp)

	if !bytes.Equal(stf.Sig, sigBytes) {
		return nil, errors.Errorf("sig bytes mismatch")
	}

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
	if err := st.VerifySpecific(bytesToSign); err != nil {
		return nil, err
	}

	return st, nil
}
