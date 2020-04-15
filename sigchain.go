package keys

import (
	"bytes"
	"crypto/sha256"
	"text/tabwriter"
	"time"

	"github.com/keys-pub/keys/ds"
	"github.com/pkg/errors"
)

// TODO: Implement merkle tree to verify global sigchain state?

// Sigchain is a chain of signed statements by a sign key.
type Sigchain struct {
	kid        ID
	statements []*Statement
	revokes    map[int]*Statement
}

// StatementPublicKeyFromID converts ID to StatementPublicKey.
func StatementPublicKeyFromID(id ID) (StatementPublicKey, error) {
	return NewEdX25519PublicKeyFromID(id)
}

// RevokeLabel is label for revoking an earlier statement
const RevokeLabel = "revoke"

// NewSigchain returns a new Sigchain for a EdX25519PublicKey.
func NewSigchain(kid ID) *Sigchain {
	return &Sigchain{
		kid:        kid,
		statements: []*Statement{},
		revokes:    map[int]*Statement{},
	}
}

// KID ...
func (s *Sigchain) KID() ID {
	return s.kid
}

// Statements are all the signed statements.
func (s Sigchain) Statements() []*Statement {
	return s.statements
}

// Spew shows formatted sigchain output.
func (s *Sigchain) Spew() (*bytes.Buffer, error) {
	var out bytes.Buffer
	w := new(tabwriter.Writer)
	w.Init(&out, 0, 8, 1, ' ', 0)
	for _, st := range s.statements {
		key := ds.Path("sigchain", st.URL())
		b, err := st.Bytes()
		if err != nil {
			return nil, err
		}
		value := string(b)
		out.Write([]byte(key))
		out.Write([]byte(" "))
		out.Write([]byte(value))
		out.Write([]byte("\n"))
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}
	return &out, nil
}

// LastSeq returns last signed statment seq (or 0 if no signed statements
// exist).
func (s Sigchain) LastSeq() int {
	if len(s.statements) == 0 {
		return 0
	}
	return s.statements[len(s.statements)-1].Seq
}

// Length of Sigchain.
func (s Sigchain) Length() int {
	return len(s.statements)
}

// Last returns last statement or nil if none.
func (s Sigchain) Last() *Statement {
	if len(s.statements) == 0 {
		return nil
	}
	return s.statements[len(s.statements)-1]
}

// IsRevoked returns true if statement was revoked.
func (s Sigchain) IsRevoked(seq int) bool {
	_, ok := s.revokes[seq]
	return ok
}

// Add signed statement to the Sigchain.
func (s *Sigchain) Add(st *Statement) error {
	if s.kid != st.KID {
		return errors.Errorf("invalid sigchain kid")
	}
	if len(st.Data) == 0 && st.Type != "revoke" {
		return errors.Errorf("no data")
	}
	if err := s.VerifyStatement(st, s.Last()); err != nil {
		return err
	}

	if st.Revoke != 0 {
		s.revokes[st.Revoke] = st
	}
	s.statements = append(s.statements, st)
	return nil
}

// AddAll pushes signed statements to the Sigchain.
func (s *Sigchain) AddAll(statements []*Statement) error {
	for _, e := range statements {
		if err := s.Add(e); err != nil {
			return err
		}
	}
	return nil
}

// SigchainHash returns hash for Sigchain Statement.
func SigchainHash(st *Statement) (*[32]byte, error) {
	b, err := st.Bytes()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return &h, nil
}

// signStatement sets the KID and Sig fields on a Signed value (that has no Sig
// yet).
func signStatement(st *Statement, signKey *EdX25519Key) error {
	if st.Sig != nil {
		return errors.Errorf("signature already set")
	}
	if st.KID != signKey.ID() {
		return errors.Errorf("sign failed: key id mismatch")
	}
	b, err := statementBytesToSign(st)
	if err != nil {
		return err
	}
	st.serialized = b
	st.Sig = signKey.SignDetached(st.serialized)
	return nil
}

// NewSigchainStatement creates a signed Statement to be added to the Sigchain.
func NewSigchainStatement(sc *Sigchain, b []byte, sk *EdX25519Key, typ string, ts time.Time) (*Statement, error) {
	if sc == nil {
		return nil, errors.Errorf("no sigchain specified")
	}
	if sc.KID() != sk.ID() {
		return nil, errors.Errorf("invalid sigchain public key")
	}

	seq := sc.LastSeq() + 1

	prevStatement := sc.Last()
	prevHash, err := sigchainPreviousHash(prevStatement)
	if err != nil {
		return nil, err
	}
	var prev []byte
	if prevHash != nil {
		prev = prevHash[:]
	}

	st := &Statement{
		Data:      b,
		KID:       sk.ID(),
		Seq:       seq,
		Prev:      prev,
		Timestamp: ts,
		Type:      typ,
	}
	if err := signStatement(st, sk); err != nil {
		return nil, err
	}
	return st, nil
}

func sigchainPreviousHash(prev *Statement) (*[32]byte, error) {
	if prev == nil {
		return nil, nil
	}
	prevHash, err := SigchainHash(prev)
	if err != nil {
		return nil, err
	}
	return prevHash, nil
}

// NewRevokeStatement creates a revoke Statement.
func NewRevokeStatement(sc *Sigchain, revoke int, sk *EdX25519Key) (*Statement, error) {
	if sc == nil {
		return nil, errors.Errorf("no sigchain specified")
	}
	if sc.KID() != sk.ID() {
		return nil, errors.Errorf("invalid sigchain public key")
	}
	if revoke < 1 {
		return nil, errors.Errorf("invalid revoke seq %d", revoke)
	}
	max := len(sc.statements)
	if revoke > max {
		return nil, errors.Errorf("invalid revoke seq %d", revoke)
	}
	if sc.IsRevoked(revoke) {
		return nil, errors.Errorf("already revoked")
	}

	seq := sc.LastSeq() + 1

	if revoke == seq {
		return nil, errors.Errorf("invalid revoke seq %d", revoke)
	}

	prev := sc.Last()
	prevHash, err := sigchainPreviousHash(prev)
	if err != nil {
		return nil, err
	}
	st := Statement{
		KID:    sc.KID(),
		Seq:    seq,
		Prev:   prevHash[:],
		Revoke: revoke,
		Type:   "revoke",
	}
	if err := signStatement(&st, sk); err != nil {
		return nil, err
	}
	return &st, nil
}

// Revoke a signed statement in the Sigchain.
func (s *Sigchain) Revoke(revoke int, sk *EdX25519Key) (*Statement, error) {
	st, err := NewRevokeStatement(s, revoke, sk)
	if err != nil {
		return nil, err
	}
	if err := s.Add(st); err != nil {
		return nil, err
	}
	return st, nil
}

// VerifyStatement verifies a signed statement against a previous statement (in a
// Sigchain).
func (s Sigchain) VerifyStatement(st *Statement, prev *Statement) error {
	if st.KID != s.kid {
		return errors.Errorf("invalid statement kid")
	}
	if err := st.Verify(); err != nil {
		return err
	}

	if prev == nil {
		if st.Seq != 1 {
			return errors.Errorf("invalid sigchain sequence expected %d, got %d", 1, st.Seq)
		}
		if st.Prev != nil {
			return errors.Errorf("invalid sigchain previous, expected empty, got %s", st.Prev)
		}
	} else {
		if st.Seq != prev.Seq+1 {
			return errors.Errorf("invalid sigchain sequence expected %d, got %d", prev.Seq+1, st.Seq)
		}
		prevHash, err := SigchainHash(prev)
		if err != nil {
			return err
		}
		if !bytes.Equal(st.Prev, prevHash[:]) {
			return errors.Errorf("invalid sigchain previous, expected %s, got %s", prevHash, st.Prev)
		}
	}

	if st.Revoke != 0 {
		if st.Revoke == st.Seq {
			return errors.Errorf("revoke self is unsupported")
		}
		if st.Revoke > st.Seq {
			return errors.Errorf("revoke index is greater than current index")
		}
		if st.Revoke < 1 {
			return errors.Errorf("revoke is less than 1")
		}
		revoked := s.Statements()[st.Revoke-1]
		if revoked.Revoke != 0 {
			return errors.Errorf("revoking a revoke is unsupported")
		}
	}

	return nil
}

// FindLast search from the last statement to the first, returning after
// If type is specified, we will search for that statement type.
// If we found a statement and it was revoked, we return nil.
func (s Sigchain) FindLast(typ string) *Statement {
	for i := len(s.statements) - 1; i >= 0; i-- {
		st := s.statements[i]
		if typ == "" {
			return st
		}
		if st.Type == typ {
			if s.IsRevoked(st.Seq) {
				return nil
			}
			return st
		}
	}
	return nil
}

// FindAll returns statements of type.
func (s Sigchain) FindAll(typ string) []*Statement {
	sts := make([]*Statement, 0, 10)
	for _, st := range s.statements {
		if typ != "" && st.Type == typ {
			if s.IsRevoked(st.Seq) {
				continue
			}
			sts = append(sts, st)
		}
	}
	return sts
}
