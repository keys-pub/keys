// Package user defines user statements, store and search.
package user

import (
	"strconv"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/json"
	"github.com/keys-pub/keys/user/validate"
	"github.com/pkg/errors"
)

// User describes a name on a service with a signed statement at a
// URL, signed into a sigchain at (KID, seq).
type User struct {
	Name    string
	KID     keys.ID
	Seq     int
	Service string
	URL     string
}

func (u User) String() string {
	s := u.Name + "@" + u.Service + "!" + u.KID.String()
	if u.Seq != 0 {
		s = s + "-" + strconv.Itoa(u.Seq)
	}
	if u.URL != "" {
		s = s + "#" + u.URL
	}
	return s
}

// ID is an identifier for a user, e.g. gabriel@github.
func (u User) ID() string {
	return u.Name + "@" + u.Service
}

// MarshalJSON marshals user to JSON.
func (u User) MarshalJSON() ([]byte, error) {
	return u.Bytes()
}

// Bytes is a serialized User.
func (u User) Bytes() ([]byte, error) {
	mes := []encoding.TextMarshaler{}

	mes = append(mes, json.String("k", u.KID.String()))
	mes = append(mes, json.String("n", u.Name))

	if u.Seq != 0 {
		mes = append(mes, json.Int("sq", u.Seq))
	}
	mes = append(mes, json.String("sr", u.Service))
	if u.URL != "" {
		mes = append(mes, json.String("u", u.URL))
	}
	return json.Marshal(mes...)
}

// Status is the status of the user statement.
type Status string

const (
	// StatusOK if user was found and verified.
	StatusOK Status = "ok"
	// StatusResourceNotFound if resource (URL) was not found.
	StatusResourceNotFound Status = "resource-not-found"
	// StatusContentNotFound if resource was found, but message was missing.
	StatusContentNotFound Status = "content-not-found"
	// StatusStatementInvalid if statement was found but was invalid.
	StatusStatementInvalid Status = "statement-invalid"
	// StatusContentInvalid if statement was valid, but other data was invalid.
	StatusContentInvalid Status = "content-invalid"

	// StatusConnFailure if there was a (possibly) temporary connection failure.
	// This could be:
	// - A connection error if not connected to the internet or unable to reach the service.
	// - A 5xx error on the server.
	// - A 4xx error except 404 (for example, 429 if rate limited).
	StatusConnFailure Status = "connection-fail"

	// StatusFailure is any other failure.
	StatusFailure Status = "fail"
	// StatusUnknown is unknown.
	StatusUnknown Status = "unknown"
)

// userFormat should stay ordered by JSON key names.
type userFormat struct {
	KID     string `json:"k"`
	Name    string `json:"n"`
	Seq     int    `json:"sq"`
	Service string `json:"sr"`
	URL     string `json:"u"`
}

// UnmarshalJSON unmarshals a user from JSON.
func (u *User) UnmarshalJSON(b []byte) error {
	var user userFormat
	err := json.Unmarshal(b, &user)
	if err != nil {
		return err
	}

	kid, err := keys.ParseID(user.KID)
	if err != nil {
		return err
	}

	u.Name = user.Name
	u.KID = kid
	u.Seq = user.Seq
	u.Service = user.Service
	u.URL = user.URL
	return nil
}

// New creates a User.
// Name and URL string are NOT normalized.
func New(kid keys.ID, service string, name string, urs string, seq int) (*User, error) {
	usr, err := newUser(kid, service, name, urs)
	if err != nil {
		return nil, err
	}
	if seq <= 0 {
		return nil, errors.Errorf("invalid seq")
	}
	usr.Seq = seq
	return usr, nil
}

func newUser(kid keys.ID, service string, name string, urs string) (*User, error) {
	usr := &User{
		KID:     kid,
		Service: service,
		Name:    name,
		URL:     urs,
	}
	if err := usr.Validate(); err != nil {
		return nil, err
	}
	return usr, nil
}

// NewForSigning returns User for signing (doesn't have remote URL yet).
// The name is normalized, for example for twitter "@Username" => "username".
func NewForSigning(kid keys.ID, service string, name string) (*User, error) {
	svc, err := validate.Lookup(service)
	if err != nil {
		return nil, err
	}
	name = svc.NormalizeName(name)
	if err := validateServiceAndName(svc, name); err != nil {
		return nil, err
	}
	return &User{
		KID:     kid,
		Service: service,
		Name:    name,
	}, nil
}

func validateServiceAndName(service validate.Validator, name string) error {
	if len(name) == 0 {
		return errors.Errorf("name is empty")
	}
	return service.ValidateName(name)
}

// Validate service and name and URL.
// If you want to request the URL and verify the remote statement, use RequestVerify.
func (u *User) Validate() error {
	if _, err := keys.ParseID(u.KID.String()); err != nil {
		return err
	}

	service, err := validate.Lookup(u.Service)
	if err != nil {
		return err
	}

	if err := validateServiceAndName(service, u.Name); err != nil {
		return err
	}

	if err := service.ValidateURL(u.Name, u.URL); err != nil {
		return err
	}
	return nil
}

// ErrUserAlreadySet is user already set in sigchain.
var ErrUserAlreadySet = errors.New("user set in sigchain already")

// NewSigchainStatement for a user to add to a Sigchain.
// Returns ErrUserAlreadySet is user already exists in the Sigchain.
func NewSigchainStatement(sc *keys.Sigchain, user *User, sk *keys.EdX25519Key, ts time.Time) (*keys.Statement, error) {
	if user == nil {
		return nil, errors.Errorf("no user specified")
	}

	if err := user.Validate(); err != nil {
		return nil, err
	}

	// Check if we have an existing user set.
	existing, err := FindInSigchain(sc)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserAlreadySet
	}

	b, err := user.MarshalJSON()
	if err != nil {
		return nil, err
	}
	st, err := keys.NewSigchainStatement(sc, b, sk, "user", ts)
	if err != nil {
		return nil, err
	}
	if st.Seq != user.Seq {
		return nil, errors.Errorf("user seq mismatch")
	}
	return st, nil
}

// Sign user into an armored message.
func (u *User) Sign(key *keys.EdX25519Key) (string, error) {
	b, err := u.MarshalJSON()
	if err != nil {
		return "", err
	}
	sig := key.Sign(b)
	// No brand for user message to keep it under 280 characters (for twitter)
	msg := encoding.EncodeSaltpack(sig, "")
	return msg, nil
}

// Verify verifies a saltpack armored message for a user.
// The message should have come from the User URL and part of a verified sigchain
// statement with matching sequence number.
func (u *User) Verify(msg string) error {
	logger.Debugf("Decoding msg: %s", msg)
	b, _, err := encoding.DecodeSaltpack(msg, false)
	if err != nil {
		return errors.Wrapf(err, "failed to user verify")
	}

	spk, err := keys.StatementPublicKeyFromID(u.KID)
	if err != nil {
		return errors.Wrapf(err, "failed to user verify")
	}

	logger.Debugf("Verifying msg...")
	bout, err := spk.Verify(b)
	if err != nil {
		return errors.Wrapf(err, "failed to user verify")
	}

	var dec User
	if err := json.Unmarshal(bout, &dec); err != nil {
		return err
	}
	logger.Debugf("User: %v", dec)
	if dec.Name == "" {
		return errors.Errorf("failed to user verify: message invalid, no name")
	}
	if dec.KID == "" {
		return errors.Errorf("failed to user verify: message invalid, no kid")
	}
	if dec.Service == "" {
		return errors.Errorf("failed to user verify: message invalid, no service")
	}

	if dec.KID != u.KID {
		return errors.Errorf("failed to user verify: kid mismatch %s != %s", u.KID, dec.KID)
	}
	if dec.Service != u.Service {
		return errors.Errorf("failed to user verify: service mismatch %s != %s", u.Service, dec.Service)
	}
	if dec.Name != u.Name {
		return errors.Errorf("failed to user verify: name mismatch %s != %s", u.Name, dec.Name)
	}

	return nil
}

// FindInSigchain returns User from a Sigchain.
// If user is invalid returns nil.
func FindInSigchain(sc *keys.Sigchain) (*User, error) {
	st := sc.FindLast("user")
	if st == nil {
		return nil, nil
	}
	var usr User
	if err := json.Unmarshal(st.Data, &usr); err != nil {
		return nil, err
	}

	if err := usr.Validate(); err != nil {
		logger.Debugf("User failed to validate in sigchain: %s", err)
		return nil, nil
	}

	return &usr, nil
}
