package keys

import (
	"encoding/json"
	"net/url"
	"strconv"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/services"
	"github.com/pkg/errors"
)

// User describes a name on a service with a signed statement at a
// URL, signed into a sigchain at (KID, seq).
type User struct {
	Name    string
	KID     ID
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

// MarshalJSON marshals user to JSON.
func (u User) MarshalJSON() ([]byte, error) {
	return u.Bytes(), nil
}

// Bytes is a serialized User.
func (u User) Bytes() []byte {
	mes := []MarshalValue{}

	mes = append(mes, NewStringEntry("k", u.KID.String()))
	mes = append(mes, NewStringEntry("n", u.Name))

	if u.Seq != 0 {
		mes = append(mes, NewIntEntry("sq", u.Seq))
	}
	mes = append(mes, NewStringEntry("sr", u.Service))
	if u.URL != "" {
		mes = append(mes, NewStringEntry("u", u.URL))
	}
	return Marshal(mes)
}

// UserStatus is the status of the user statement.
type UserStatus string

const (
	// UserStatusOK if user was found and verified.
	UserStatusOK UserStatus = "ok"
	// UserStatusResourceNotFound if resource (URL) was not found.
	UserStatusResourceNotFound UserStatus = "resource-not-found"
	// UserStatusContentNotFound if resource was found, but message was missing.
	UserStatusContentNotFound UserStatus = "content-not-found"
	// UserStatusStatementInvalid if statement was found but was invalid.
	UserStatusStatementInvalid UserStatus = "statement-invalid"
	// UserStatusContentInvalid if statement was valid, but other data was invalid.
	UserStatusContentInvalid UserStatus = "content-invalid"
	// UserStatusConnFailure if there was a network connection failure.
	UserStatusConnFailure UserStatus = "connection-fail"
	// UserStatusFailure is any other failure.
	UserStatusFailure UserStatus = "fail"
	// UserStatusUnknown is unknown.
	UserStatusUnknown UserStatus = "unknown"
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

	kid, err := ParseID(user.KID)
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

// NewUser returns User used in a signing statement.
func NewUser(ust *UserStore, kid ID, service string, name string, rawurl string, seq int) (*User, error) {
	svc, err := services.NewService(service)
	if err != nil {
		return nil, err
	}

	user, err := newUser(ust, kid, svc, name, rawurl)
	if err != nil {
		return nil, err
	}
	if seq <= 0 {
		return nil, errors.Errorf("invalid seq")
	}
	user.Seq = seq
	return user, nil
}

func newUser(ust *UserStore, kid ID, service services.Service, name string, rawurl string) (*User, error) {
	name = service.NormalizeUsername(name)
	url, err := normalizeURL(rawurl)
	if err != nil {
		return nil, err
	}
	user := &User{
		KID:     kid,
		Service: service.Name(),
		Name:    name,
		URL:     url,
	}
	if err := ust.validate(user); err != nil {
		return nil, err
	}
	return user, nil
}

// NewUserForSigning returns User for signing (doesn't have remote URL yet).
func NewUserForSigning(ust *UserStore, kid ID, service string, name string) (*User, error) {
	svc, err := services.NewService(service)
	if err != nil {
		return nil, err
	}
	name = svc.NormalizeUsername(name)
	if err := ust.validateServiceAndName(svc, name); err != nil {
		return nil, err
	}
	return &User{
		KID:     kid,
		Service: svc.Name(),
		Name:    name,
	}, nil
}

func normalizeURL(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (u *UserStore) validateServiceAndName(service services.Service, name string) error {
	if len(name) == 0 {
		return errors.Errorf("name is empty")
	}
	return service.ValidateUsername(name)
}

func (u *UserStore) validate(user *User) error {
	service, err := services.NewService(user.Service)
	if err != nil {
		return err
	}

	if err := u.validateServiceAndName(service, user.Name); err != nil {
		return err
	}
	ur, err := url.Parse(user.URL)
	if err != nil {
		return err
	}

	if _, err := service.ValidateURL(user.Name, ur); err != nil {
		return err
	}
	return nil
}

// ErrUserAlreadySet is user already set in sigchain.
var ErrUserAlreadySet = errors.New("user set in sigchain already")

// GenerateUserStatement for a user to add to the sigchain.
// Returns ErrUserAlreadySet is user already exists in the sigchain.
func GenerateUserStatement(sc *Sigchain, user *User, sk *EdX25519Key, ts time.Time) (*Statement, error) {
	if user == nil {
		return nil, errors.Errorf("no user specified")
	}
	// Check if we have an existing user set.
	existing, err := sc.User()
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserAlreadySet
	}

	b, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	st, err := GenerateStatement(sc, b, sk, "user", ts)
	if err != nil {
		return nil, err
	}
	if st.Seq != user.Seq {
		return nil, errors.Errorf("user seq mismatch")
	}
	return st, nil
}

// Sign user into an armored message.
func (u *User) Sign(key *EdX25519Key) (string, error) {
	b, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	sig := key.Sign(b)
	// No brand for user message to keep it under 280 characters (for twitter)
	msg := encoding.EncodeSaltpack(sig, "")
	return msg, nil
}

// VerifyUser armored message for a user.
// If user is specified, we will verify it matches the User in the verified
// message.
func VerifyUser(msg string, spk SigchainPublicKey, user *User) (*User, error) {
	logger.Debugf("Decoding msg: %s", msg)
	b, _, err := encoding.DecodeSaltpack(msg, false)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Verifying msg...")
	bout, err := spk.Verify(b)
	if err != nil {
		return nil, err
	}

	var userDec User
	if err := json.Unmarshal(bout, &userDec); err != nil {
		return nil, err
	}
	logger.Debugf("User: %v", userDec)
	if userDec.Name == "" {
		return nil, errors.Errorf("user message invalid: no name")
	}
	if userDec.KID == "" {
		return nil, errors.Errorf("user message invalid: no kid")
	}
	if userDec.Service == "" {
		return nil, errors.Errorf("user message invalid: no service")
	}

	if user != nil {
		if userDec.KID != user.KID {
			return nil, errors.Errorf("kid mismatch %s != %s", user.KID, userDec.KID)
		}
		if userDec.Service != user.Service {
			return nil, errors.Errorf("service mismatch %s != %s", user.Service, userDec.Service)
		}
		if userDec.Name != user.Name {
			return nil, errors.Errorf("name mismatch %s != %s", user.Name, userDec.Name)
		}
	}

	return &userDec, nil
}
