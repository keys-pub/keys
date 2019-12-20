package keys

import (
	"context"
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

// UserCheck is the result of a user check.
type UserCheck struct {
	Err        string     `json:"err,omitempty"`
	Status     UserStatus `json:"status"`
	Timestamp  time.Time  `json:"ts"`
	User       *User      `json:"user"`
	VerifiedAt time.Time  `json:"vts"`
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

	mes = append(mes, NewStringEntry("kid", u.KID.String()))
	mes = append(mes, NewStringEntry("name", u.Name))

	if u.Seq != 0 {
		mes = append(mes, NewIntEntry("seq", u.Seq))
	}
	mes = append(mes, NewStringEntry("service", u.Service))
	if u.URL != "" {
		mes = append(mes, NewStringEntry("url", u.URL))
	}
	return Marshal(mes)
}

// UserStatus is the status of the user statement.
type UserStatus string

const (
	// UserStatusOK if user was found and verified.
	UserStatusOK UserStatus = "ok"
	// UserStatusResourceNotFound if resources was not found.
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
	KID     string `json:"kid"`
	Name    string `json:"name"`
	Seq     int    `json:"seq"`
	Service string `json:"service"`
	URL     string `json:"url"`
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
func NewUser(ctx *UserContext, kid ID, service string, name string, rawurl string, seq int) (*User, error) {
	user, err := newUser(ctx, kid, service, name, rawurl)
	if err != nil {
		return nil, err
	}
	if seq <= 0 {
		return nil, errors.Errorf("invalid seq")
	}
	user.Seq = seq
	return user, nil
}

func newUser(ctx *UserContext, kid ID, service string, name string, rawurl string) (*User, error) {
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
	if err := ctx.validate(user); err != nil {
		return nil, err
	}
	return user, nil
}

// NewUserForSigning returns User for signing (doesn't have remote URL yet).
func NewUserForSigning(uc *UserContext, kid ID, service string, name string) (*User, error) {
	name = normalizeName(service, name)
	if err := uc.validateServiceAndName(service, name); err != nil {
		return nil, err
	}
	return &User{
		KID:     kid,
		Service: service,
		Name:    name,
	}, nil
}

// UserContext is the environment for user checks.
type UserContext struct {
	req             Requestor
	nowFn           func() time.Time
	enabledServices *StringSet
}

// NewDefaultUserContext creates default UserContext.
func NewDefaultUserContext() *UserContext {
	services := []string{"twitter", "github"}
	req := NewHTTPRequestor()
	nowFn := time.Now
	uc, err := NewUserContext(services, req, nowFn)
	if err != nil {
		panic(err)
	}
	return uc
}

// NewTestUserContext creates UserContext for testing.
func NewTestUserContext(req Requestor, nowFn func() time.Time) *UserContext {
	services := []string{"twitter", "github"}
	uc, err := NewUserContext(services, req, nowFn)
	if err != nil {
		panic(err)
	}
	return uc
}

// NewUserContext creates UserContext.
// Requestor, for example, on GCP this would use the urlfetch package.
func NewUserContext(services []string, req Requestor, nowFn func() time.Time) (*UserContext, error) {
	for _, service := range services {
		if err := validateServiceSupported(service); err != nil {
			return nil, err
		}
	}
	return &UserContext{
		enabledServices: NewStringSet(services...),
		nowFn:           nowFn,
		req:             req,
	}, nil
}

// Now returns current time.
func (u *UserContext) Now() time.Time {
	return u.nowFn()
}

// Requestor ...
func (u *UserContext) Requestor() Requestor {
	return u.req
}

// CheckSigchain returns user checks for users in the sigchain.
func (u *UserContext) CheckSigchain(ctx context.Context, sc *Sigchain) ([]*UserCheck, error) {
	users := sc.Users()
	checked := make([]*UserCheck, 0, len(users))
	for _, user := range users {
		check, err := u.Check(ctx, user, sc.SignPublicKey())
		if err != nil {
			return nil, err
		}
		checked = append(checked, check)
	}
	return checked, nil
}

// Check checks and verifies the user statement URL.
func (u *UserContext) Check(ctx context.Context, user *User, spk SignPublicKey) (*UserCheck, error) {
	if user == nil {
		return nil, errors.Errorf("no user specified")
	}
	logger.Infof("Checking user %s", user.String())
	ur, err := url.Parse(user.URL)
	if err != nil {
		logger.Warningf("Failed to parse user url: %s", err)
		return &UserCheck{
			Err:       err.Error(),
			Status:    UserStatusFailure,
			Timestamp: u.Now(),
			User:      user,
		}, nil
	}
	logger.Infof("Requesting %s", ur)
	body, err := u.req.RequestURL(ctx, ur)
	if err != nil {
		if errHTTP, ok := errors.Cause(err).(ErrHTTP); ok && errHTTP.StatusCode == 404 {
			return &UserCheck{
				Err:    err.Error(),
				Status: UserStatusResourceNotFound,
				User:   user,
			}, nil
		}
		return &UserCheck{
			Err:       err.Error(),
			Status:    UserStatusConnFailure,
			Timestamp: u.Now(),
			User:      user,
		}, nil
	}

	msg := findSaltpackMessageInHTML(string(body), "")
	if msg == "" {
		logger.Warningf("User statement content not found")
		return &UserCheck{
			Err:       "user signed message content not found",
			Status:    UserStatusContentNotFound,
			Timestamp: u.Now(),
			User:      user,
		}, nil
	}

	_, err = VerifyUser(msg, spk, user)
	if err != nil {
		logger.Warningf("Failed to verify statement: %s", err)
		return &UserCheck{
			Err:       err.Error(),
			Status:    UserStatusFailure,
			Timestamp: u.Now(),
			User:      user,
		}, nil
	}

	logger.Infof("Verified %s", user)
	return &UserCheck{
		Status:     UserStatusOK,
		Timestamp:  u.Now(),
		User:       user,
		VerifiedAt: u.Now(),
	}, nil
}

func validateServiceSupported(service string) error {
	// TODO: gitlab
	switch service {
	case "twitter", "github":
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
	case "github":
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
	case "twitter":
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
	if service == "twitter" && len(name) > 0 && name[0] == '@' {
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

func (u *UserContext) validateServiceAndName(service string, name string) error {
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
	if service == "twitter" && name[0] == '@' {
		name = name[1:]
	}

	isASCII := IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("user name has non-ASCII characters")
	}
	hu := hasUpper(name)
	if hu {
		return errors.Errorf("user name should be lowercase")
	}

	if service == "twitter" && len(name) > 15 {
		return errors.Errorf("twitter name too long")
	}

	if service == "github" && len(name) > 39 {
		return errors.Errorf("github name too long")
	}

	return nil
}

func (u *UserContext) validate(user *User) error {
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
func GenerateUserStatement(sc *Sigchain, user *User, sk *SignKey, ts time.Time) (*Statement, error) {
	if user == nil {
		return nil, errors.Errorf("no user specified")
	}
	// Check if we have an existing user set with the same name and service
	users := sc.Users()
	for _, euser := range users {
		if euser.Service == user.Service && euser.Name == user.Name {
			return nil, ErrUserAlreadySet
		}
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

// ValidateStatement returns error if statement is not a valid user statement.
func (u *UserContext) ValidateStatement(st *Statement) error {
	if st.Type != "user" {
		return errors.Errorf("invalid user statement: %s != %s", st.Type, "user")
	}
	var user User
	if err := json.Unmarshal(st.Data, &user); err != nil {
		return err
	}
	if err := u.validate(&user); err != nil {
		return err
	}
	return nil
}

// Sign user into an armored message.
func (u *User) Sign(key *SignKey) (string, error) {
	b, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	sig := key.Sign(b)
	msg := EncodeSaltpackMessage(sig, "")
	return msg, nil
}

// VerifyUser armored message for a user.
// If user is specified, we will verify it matches the User in the verified
// message.
func VerifyUser(msg string, spk SignPublicKey, user *User) (*User, error) {
	b, err := DecodeSaltpackMessage(msg, "")
	if err != nil {
		return nil, err
	}

	bout, err := Verify(b, spk)
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
