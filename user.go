package keys

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	user, err := newUser(ust, kid, service, name, rawurl)
	if err != nil {
		return nil, err
	}
	if seq <= 0 {
		return nil, errors.Errorf("invalid seq")
	}
	user.Seq = seq
	return user, nil
}

func newUser(ust *UserStore, kid ID, service string, name string, rawurl string) (*User, error) {
	name = normalizeName(service, name)
	url, err := normalizeURL(rawurl)
	if err != nil {
		return nil, err
	}
	user := &User{
		KID:     kid,
		Service: service,
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
	name = normalizeName(service, name)
	if err := ust.validateServiceAndName(service, name); err != nil {
		return nil, err
	}
	return &User{
		KID:     kid,
		Service: service,
		Name:    name,
	}, nil
}

func validateServiceSupported(service string) error {
	// TODO: gitlab
	switch service {
	case Twitter, Github:
	default:
		return errors.Errorf("invalid service %s", service)
	}
	return nil
}

// verifyURL verifies URL for service.
// For github, the url should be https://gist.github.com/{name}/{gistid}.
// For twitter, the url should be https://twitter.com/{name}/status/{id}.
func verifyURL(service string, name string, u *url.URL) error {
	switch service {
	case Github:
		if u.Scheme != "https" {
			return errors.Errorf("invalid scheme for url %s", u)
		}
		if u.Host != "gist.github.com" {
			return errors.Errorf("invalid host for url %s", u)
		}
		path := u.Path
		path = strings.TrimPrefix(path, "/")
		paths := strings.Split(path, "/")
		if len(paths) != 2 {
			return errors.Errorf("path invalid %s for url %s", paths, u)
		}
		if paths[0] != name {
			return errors.Errorf("path invalid (name mismatch) %s != %s", paths[0], name)
		}
		return nil
	case Twitter:
		if u.Scheme != "https" {
			return errors.Errorf("invalid scheme for url %s", u)
		}
		if u.Host != "twitter.com" {
			return errors.Errorf("invalid host for url %s", u)
		}
		path := u.Path
		path = strings.TrimPrefix(path, "/")
		paths := strings.Split(path, "/")
		if len(paths) != 3 {
			return errors.Errorf("path invalid %s for url %s", paths, u)
		}
		if paths[0] != name {
			return errors.Errorf("path invalid (name mismatch) for url %s", u)
		}
		return nil
	default:
		return errors.Errorf("unknown service %s", service)
	}
}

func normalizeName(service string, name string) string {
	if isTwitter(service) && len(name) > 0 && name[0] == '@' {
		return name[1:]
	}
	return name
}

func normalizeURL(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// Twitter service name.
const Twitter = "twitter"

// Github service name.
const Github = "github"

func isTwitter(s string) bool {
	switch s {
	case Twitter:
		return true
	default:
		return false
	}
}

func (u *UserStore) validateServiceAndName(service string, name string) error {
	if len(service) == 0 {
		return errors.Errorf("service is empty")
	}

	if err := validateServiceSupported(service); err != nil {
		return err
	}

	if u.enabledServices.Size() == 0 {
		return errors.Errorf("no services enabled")
	}

	if !u.enabledServices.Contains(service) {
		return errors.Errorf("%s service is not enabled", service)
	}

	if len(name) == 0 {
		return errors.Errorf("name is empty")
	}

	// Normalize twitter name
	if isTwitter(service) && name[0] == '@' {
		name = name[1:]
	}

	isASCII := IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("user name has non-ASCII characters")
	}
	hu := HasUpper(name)
	if hu {
		return errors.Errorf("user name should be lowercase")
	}

	if isTwitter(service) && len(name) > 15 {
		return errors.Errorf("twitter name too long")
	}

	if service == Github && len(name) > 39 {
		return errors.Errorf("github name too long")
	}

	return nil
}

func (u *UserStore) validate(user *User) error {
	if err := u.validateServiceAndName(user.Service, user.Name); err != nil {
		return err
	}
	ur, err := url.Parse(user.URL)
	if err != nil {
		return err
	}
	if err := verifyURL(user.Service, user.Name, ur); err != nil {
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
	msg := EncodeSaltpack(sig, "")
	return msg, nil
}

// VerifyUser armored message for a user.
// If user is specified, we will verify it matches the User in the verified
// message.
func VerifyUser(msg string, spk SigchainPublicKey, user *User) (*User, error) {
	b, _, err := DecodeSaltpack(msg, false)
	if err != nil {
		return nil, err
	}

	bout, err := spk.Verify(b)
	if err != nil {
		return nil, err
	}

	var userDec User
	if err := json.Unmarshal(bout, &userDec); err != nil {
		return nil, err
	}
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
