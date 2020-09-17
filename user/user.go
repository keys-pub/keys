// Package user defines user statements, store and search.
package user

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/json"
	"github.com/keys-pub/keys/link"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
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
	svc, err := link.NewService(service)
	if err != nil {
		return nil, err
	}

	usr, err := newUser(kid, svc, name, urs)
	if err != nil {
		return nil, err
	}
	if seq <= 0 {
		return nil, errors.Errorf("invalid seq")
	}
	usr.Seq = seq
	return usr, nil
}

func newUser(kid keys.ID, service link.Service, name string, urs string) (*User, error) {
	usr := &User{
		KID:     kid,
		Service: service.ID(),
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
	svc, err := link.NewService(service)
	if err != nil {
		return nil, err
	}
	name = svc.NormalizeName(name)
	if err := validateServiceAndName(svc, name); err != nil {
		return nil, err
	}
	return &User{
		KID:     kid,
		Service: svc.ID(),
		Name:    name,
	}, nil
}

func validateServiceAndName(service link.Service, name string) error {
	if len(name) == 0 {
		return errors.Errorf("name is empty")
	}
	return service.ValidateName(name)
}

// Validate service and name and URL.
// If you want to request the URL and verify the remote statement, use RequestVerify.
func (u *User) Validate() error {
	service, err := link.NewService(u.Service)
	if err != nil {
		return err
	}

	if err := validateServiceAndName(service, u.Name); err != nil {
		return err
	}

	if _, err := service.ValidateURLString(u.Name, u.URL); err != nil {
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

// Verify armored message for a user.
func Verify(msg string, usr *User) error {
	logger.Debugf("Decoding msg: %s", msg)
	b, _, err := encoding.DecodeSaltpack(msg, false)
	if err != nil {
		return errors.Wrapf(err, "failed to user verify")
	}

	spk, err := keys.StatementPublicKeyFromID(usr.KID)
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

	if dec.KID != usr.KID {
		return errors.Errorf("failed to user verify: kid mismatch %s != %s", usr.KID, dec.KID)
	}
	if dec.Service != usr.Service {
		return errors.Errorf("failed to user verify: service mismatch %s != %s", usr.Service, dec.Service)
	}
	if dec.Name != usr.Name {
		return errors.Errorf("failed to user verify: name mismatch %s != %s", usr.Name, dec.Name)
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
		return nil, nil
	}

	return &usr, nil
}

// MockStatement for testing.
func MockStatement(key *keys.EdX25519Key, sc *keys.Sigchain, name string, service string, req *request.MockRequestor, clock tsutil.Clock) (*keys.Statement, error) {
	us, err := NewForSigning(key.ID(), service, name)
	if err != nil {
		return nil, err
	}
	msg, err := us.Sign(key)
	if err != nil {
		return nil, err
	}

	urs := ""
	switch service {
	case "github":
		urs = fmt.Sprintf("https://gist.github.com/%s/1", name)
	case "twitter":
		urs = fmt.Sprintf("https://mobile.twitter.com/%s/status/1", name)
	case "echo":
		urs = "test://echo/" + name + "/" + key.ID().String() + "/" + url.QueryEscape(strings.ReplaceAll(msg, "\n", " "))
	case "https":
		urs = "https://" + name
	default:
		return nil, errors.Errorf("unsupported service for mock")
	}

	usr, err := New(key.ID(), service, name, urs, sc.LastSeq()+1)
	if err != nil {
		return nil, err
	}
	st, err := NewSigchainStatement(sc, usr, key, clock.Now())
	if err != nil {
		return nil, err
	}

	req.SetResponse(urs, []byte(msg))

	if err := sc.Add(st); err != nil {
		return nil, err
	}

	return st, nil
}
