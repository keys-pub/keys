package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
)

// Sigchain is a chain of signed statements by a sign key.
type Sigchain struct {
	kid        ID
	spk        SignPublicKey
	statements []*Statement
	revokes    map[int]*Statement
	readOnly   bool
}

// RevokeLabel is label for revoking an earlier statement
const RevokeLabel = "revoke"

// NewSigchain returns a new Sigchain for a SignPublicKey.
func NewSigchain(spk SignPublicKey) *Sigchain {
	return &Sigchain{
		kid:        SignPublicKeyID(spk),
		spk:        spk,
		statements: []*Statement{},
		revokes:    map[int]*Statement{},
	}
}

// NewSigchainForKID returns a new Sigchain for a sign public key ID.
func NewSigchainForKID(kid ID) (*Sigchain, error) {
	spk, err := DecodeSignPublicKey(kid.String())
	if err != nil {
		return nil, err
	}
	return NewSigchain(spk), nil
}

// KID is the sign public key ID.
func (s *Sigchain) KID() ID {
	return s.kid
}

// ID is the sign public key ID.
func (s *Sigchain) ID() ID {
	return s.kid
}

// SetReadOnly to set read only.
func (s *Sigchain) SetReadOnly(b bool) {
	s.readOnly = b
}

// Statements are all the signed statements.
func (s Sigchain) Statements() []*Statement {
	return s.statements
}

// SignPublicKey is sign public key for sigchain.
func (s *Sigchain) SignPublicKey() SignPublicKey {
	return s.spk
}

// Spew shows formatted sigchain output.
func (s *Sigchain) Spew() (*bytes.Buffer, error) {
	var out bytes.Buffer
	w := new(tabwriter.Writer)
	w.Init(&out, 0, 8, 1, ' ', 0)
	for _, st := range s.statements {
		key := st.URLPath()
		value := string(st.Bytes())
		out.Write([]byte(key))
		out.Write([]byte(" "))
		out.Write([]byte(value))
		out.Write([]byte("\n"))
	}
	w.Flush()
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
	if SignPublicKeyID(s.spk) != st.KID {
		return errors.Errorf("invalid sigchain kid")
	}
	if len(st.Data) == 0 && st.Type != "revoke" {
		return errors.Errorf("no data")
	}
	if err := s.Verify(st, s.Last()); err != nil {
		return err
	}

	if s.readOnly {
		return errors.Errorf("sigchain is read only")
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
	h := sha256.Sum256(st.Bytes())
	return &h, nil
}

// signStatement sets the KID and Sig fields on a Signed value (that has no Sig
// yet).
func signStatement(st *Statement, signKey *SignKey) error {
	if st.Sig != nil {
		return errors.Errorf("signature already set")
	}
	if st.KID != SignPublicKeyID(signKey.PublicKey) {
		return errors.Errorf("sign failed: key mismatch")
	}
	st.serialized = statementBytesToSign(st)
	st.Sig = signKey.SignDetached(st.serialized)
	return nil
}

// GenerateStatement creates Statement to be added to the Sigchain.
func GenerateStatement(sc *Sigchain, b []byte, sk *SignKey, typ string, ts time.Time) (*Statement, error) {
	if sc == nil {
		return nil, errors.Errorf("no sigchain specified")
	}
	if !bytes.Equal(sc.spk[:], sk.PublicKey[:]) {
		return nil, errors.Errorf("invalid sigchain sign key")
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
		KID:       sk.ID,
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

// GenerateRevoke creates a revoke Statement.
func GenerateRevoke(sc *Sigchain, revoke int, sk *SignKey) (*Statement, error) {
	if sc == nil {
		return nil, errors.Errorf("no sigchain specified")
	}
	if !bytes.Equal(sc.spk[:], sk.PublicKey[:]) {
		return nil, errors.Errorf("invalid sigchain sign key")
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
		KID:    SignPublicKeyID(sc.spk),
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
func (s *Sigchain) Revoke(revoke int, sk *SignKey) (*Statement, error) {
	st, err := GenerateRevoke(s, revoke, sk)
	if err != nil {
		return nil, err
	}
	if s.readOnly {
		return nil, errors.Errorf("sigchain is read only")
	}
	if err := s.Add(st); err != nil {
		return nil, err
	}
	return st, nil
}

// Verify verifies a signed statement against a previous statement (in a
// Sigchain).
func (s Sigchain) Verify(st *Statement, prev *Statement) error {
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

// BoxPublicKeySigchainType is a type for sigchain statement.
const BoxPublicKeySigchainType = "bpk"

// BoxPublicKey returns current box public key.
func (s *Sigchain) BoxPublicKey() BoxPublicKey {
	st := s.FindLast(BoxPublicKeySigchainType)
	if st == nil {
		return nil
	}
	if len(st.Data) != BoxPublicKeySize {
		logger.Warningf("invalid box public key bytes in sigchain %s", s.ID)
		return nil
	}
	bpk := BoxPublicKey(Bytes32(st.Data))
	return bpk
}

// BoxPublicKeys returns all box public keys (not revoked) in the sigchain.
func (s *Sigchain) BoxPublicKeys() []BoxPublicKey {
	sts := s.FindAll(BoxPublicKeySigchainType)
	bpks := make([]BoxPublicKey, 0, len(sts))
	for _, st := range sts {
		if len(st.Data) != BoxPublicKeySize {
			logger.Warningf("invalid box public key bytes in sigchain %s", s.ID)
			return nil
		}
		bpk := BoxPublicKey(Bytes32(st.Data))
		bpks = append(bpks, bpk)
	}
	return bpks
}

// PublicKey from the Sigchain. The Sigchain implements the PublicKey interface,
// so it returns itself.
func (s *Sigchain) PublicKey() PublicKey {
	return s
}

// Users (statements) signed into the sigchain.
func (s *Sigchain) Users() []*User {
	sts := s.FindAll("user")
	users := make([]*User, 0, len(sts))
	for _, st := range sts {
		var user User
		if err := json.Unmarshal(st.Data, &user); err != nil {
			logger.Warningf("Invalid user in sigchain: %+v", err)
			continue
		}
		users = append(users, &user)
	}
	return users
}

// GenerateSigchain ...
func GenerateSigchain(key Key, ts time.Time) *Sigchain {
	sc := NewSigchain(key.SignKey().PublicKey)
	st, err := GenerateStatement(sc, key.BoxKey().PublicKey[:], key.SignKey(), BoxPublicKeySigchainType, ts)
	if err != nil {
		panic(err)
	}
	if err := sc.Add(st); err != nil {
		panic(err)
	}
	return sc
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
