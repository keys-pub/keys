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
	Name      string
	KID       ID
	Seq       int
	Service   string
	URL       string
	CheckedAt time.Time
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
	mes := []MarshalValue{
		NewStringEntry("kid", u.KID.String()),
		NewStringEntry("name", u.Name),
	}
	if u.Seq != 0 {
		mes = append(mes, NewIntEntry("seq", u.Seq))
	}
	mes = append(mes, NewStringEntry("service", u.Service))
	if u.URL != "" {
		mes = append(mes, NewStringEntry("url", u.URL))
	}
	if !u.CheckedAt.IsZero() {
		mes = append(mes, NewStringEntry("ucts", u.CheckedAt.Format(RFC3339Milli)))
	}
	return Marshal(mes)
}

type userFormat struct {
	KID       string `json:"kid"`
	Name      string `json:"name"`
	Seq       int    `json:"seq"`
	Service   string `json:"service"`
	URL       string `json:"url"`
	CheckedAt string `json:"ucts"`
}

// UnmarshalJSON unmarshals a user from JSON.
func (u *User) UnmarshalJSON(b []byte) error {
	var usr userFormat
	err := json.Unmarshal(b, &usr)
	if err != nil {
		return err
	}

	cts := time.Time{}
	if usr.CheckedAt != "" {
		t, err := time.Parse(RFC3339Milli, usr.CheckedAt)
		if err != nil {
			return err
		}
		cts = t
	}
	kid, err := ParseID(usr.KID)
	if err != nil {
		return err
	}

	u.Name = usr.Name
	u.KID = kid
	u.Seq = usr.Seq
	u.Service = usr.Service
	u.URL = usr.URL
	u.CheckedAt = cts
	return nil
}

// NewUser returns User used in a signing statement.
func NewUser(ctx *UserContext, kid ID, service string, name string, rawurl string, seq int) (*User, error) {
	usr, err := newUser(ctx, kid, service, name, rawurl)
	if err != nil {
		return nil, err
	}
	if seq <= 0 {
		return nil, errors.Errorf("invalid seq")
	}
	usr.Seq = seq
	return usr, nil
}

func newUser(ctx *UserContext, kid ID, service string, name string, rawurl string) (*User, error) {
	name = normalizeName(service, name)
	url, err := normalizeURL(rawurl)
	if err != nil {
		return nil, err
	}
	usr := &User{
		KID:     kid,
		Service: service,
		Name:    name,
		URL:     url,
	}
	if err := ctx.validate(usr); err != nil {
		return nil, err
	}
	return usr, nil
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
	testUnstable    int
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

// Check returns verified user statements URL in sigchain.
func (u *UserContext) Check(ctx context.Context, sc *Sigchain) ([]*User, error) {
	usrs := sc.Users()
	for _, usr := range usrs {
		if err := u.CheckWithKey(ctx, usr, sc.SignPublicKey()); err != nil {
			return nil, err
		}
		usr.CheckedAt = u.Now()
	}
	return usrs, nil
}

// CheckWithKey verified the user statement URL.
func (u *UserContext) CheckWithKey(ctx context.Context, usr *User, spk SignPublicKey) error {
	if usr == nil {
		return errors.Errorf("no user specified")
	}
	logger.Infof("Checking %s", usr.String())
	ur, err := url.Parse(usr.URL)
	if err != nil {
		return err
	}
	logger.Infof("Requesting %s", ur)
	body, err := u.req.RequestURL(ctx, ur)
	if err != nil {
		return err
	}

	msg, err := findStringInHTML(string(body))
	if err != nil {
		return err
	}
	if msg == "" {
		return errors.Errorf("content not found")
	}

	_, err = VerifyUser(msg, spk, usr)
	if err != nil {
		return err
	}

	logger.Infof("Verified %s", usr)
	return nil
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

func (u *UserContext) validate(usr *User) error {
	if err := u.validateServiceAndName(usr.Service, usr.Name); err != nil {
		return err
	}
	ur, err := url.Parse(usr.URL)
	if err != nil {
		return err
	}
	if err := verifyURL(usr.Service, usr.Name, ur); err != nil {
		return err
	}
	return nil
}

// ErrUserAlreadySet is user already set in sigchain.
var ErrUserAlreadySet = errors.New("user set in sigchain already")

// GenerateUserStatement for a user to add to the sigchain.
func GenerateUserStatement(sc *Sigchain, usr *User, sk *SignKey, ts time.Time) (*Statement, error) {
	if usr == nil {
		return nil, errors.Errorf("no user specified")
	}
	// Check if we have an existing user set with the same name and service
	usrs := sc.Users()
	for _, eusr := range usrs {
		if eusr.Service == usr.Service && eusr.Name == usr.Name {
			return nil, ErrUserAlreadySet
		}
	}

	b, err := json.Marshal(usr)
	if err != nil {
		return nil, err
	}
	st, err := GenerateStatement(sc, b, sk, "user", ts)
	if err != nil {
		return nil, err
	}
	if st.Seq != usr.Seq {
		return nil, errors.Errorf("user seq mismatch")
	}
	return st, nil
}

// ValidateStatement returns error if statement is not a valid user statement.
func (u *UserContext) ValidateStatement(st *Statement) error {
	if st.Type != "user" {
		return errors.Errorf("invalid user statement: %s != %s", st.Type, "user")
	}
	var usr User
	if err := json.Unmarshal(st.Data, &usr); err != nil {
		return err
	}
	if err := u.validate(&usr); err != nil {
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
	content := MustEncode(sig, Base62)
	content = breakString(content, 15, 4)
	content = content + "."
	msg := saltpackStart + "\n" + content + "\n" + saltpackEnd
	return msg, nil
}

// VerifyUser armored message for a user.
// If usr is specified, we will verify it matches the User in the verified
// message.
func VerifyUser(msg string, spk SignPublicKey, usr *User) (*User, error) {
	trim, err := trimHTML(msg)
	if err != nil {
		return nil, err
	}
	logger.Infof("Decoding %s", trim)
	b, err := Decode(trim, Base62)
	if err != nil {
		return nil, err
	}

	bout, err := Verify(b, spk)
	if err != nil {
		return nil, err
	}

	var usrDec User
	if err := json.Unmarshal(bout, &usrDec); err != nil {
		return nil, err
	}
	if usrDec.Name == "" {
		return nil, errors.Errorf("user message invalid: no name")
	}
	if usrDec.KID == "" {
		return nil, errors.Errorf("user message invalid: no kid")
	}
	if usrDec.Service == "" {
		return nil, errors.Errorf("user message invalid: no service")
	}

	if usr != nil {
		if usrDec.KID != usr.KID {
			return nil, errors.Errorf("kid mismatch %s != %s", usr.KID, usrDec.KID)
		}
		if usrDec.Service != usr.Service {
			return nil, errors.Errorf("service mismatch %s != %s", usr.Service, usrDec.Service)
		}
		if usrDec.Name != usr.Name {
			return nil, errors.Errorf("name mismatch %s != %s", usr.Name, usrDec.Name)
		}
	}

	return &usrDec, nil
}
