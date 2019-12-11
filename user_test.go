package keys

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TODO: Mock http requests

func TestNewUserForTwitterSigning(t *testing.T) {
	EnableServices("twitter")
	defer DisableServices()
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	usr, err := NewUserForSigning(key.ID(), "twitter", "123456789012345")
	require.NoError(t, err)
	msg, err := usr.Sign(key.SignKey())
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	t.Logf("Length: %d", len(msg))
	require.False(t, len(msg) > 280)
}

func TestNewUserMarshal(t *testing.T) {
	EnableServices("twitter")
	defer DisableServices()
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	kid := key.ID()
	usr, err := NewUser(kid, "twitter", "123456789012345", "https://twitter.com/123456789012345/status/1234567890", 1)
	require.NoError(t, err)
	b, err := json.Marshal(usr)
	require.NoError(t, err)
	require.Equal(t, `{"kid":"HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec","name":"123456789012345","seq":1,"service":"twitter","url":"https://twitter.com/123456789012345/status/1234567890"}`, string(b))

	var usrOut User
	err = json.Unmarshal(b, &usrOut)
	require.NoError(t, err)
	require.Equal(t, usr.Name, usrOut.Name)
	require.Equal(t, usr.Seq, usrOut.Seq)
	require.Equal(t, usr.KID, usrOut.KID)
	require.Equal(t, usr.Service, usrOut.Service)
	require.Equal(t, usr.URL, usrOut.URL)
	require.True(t, usrOut.CheckedAt.IsZero())

	usr2, err := NewUser(kid, "twitter", "123456789012345", "https://twitter.com/123456789012345/status/1234567890", 1)
	require.NoError(t, err)
	usr2.CheckedAt = TimeFromMillis(1234567890000)
	b2, err := json.Marshal(usr2)
	require.NoError(t, err)
	require.Equal(t, `{"kid":"HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec","name":"123456789012345","seq":1,"service":"twitter","url":"https://twitter.com/123456789012345/status/1234567890","ucts":"2009-02-13T15:31:30.000-08:00"}`, string(b2))

	var usrOut2 User
	err = json.Unmarshal(b2, &usrOut2)
	require.NoError(t, err)
	require.Equal(t, usr2.Name, usrOut2.Name)
	require.Equal(t, usr2.Seq, usrOut2.Seq)
	require.Equal(t, usr2.KID, usrOut2.KID)
	require.Equal(t, usr2.Service, usrOut2.Service)
	require.Equal(t, usr2.URL, usrOut2.URL)
	require.Equal(t, usr2.CheckedAt, usrOut2.CheckedAt)

	usr, err = NewUserForSigning(kid, "twitter", "123456789012345")
	require.NoError(t, err)
	b, err = json.Marshal(usr)
	require.NoError(t, err)
	require.Equal(t, `{"kid":"HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec","name":"123456789012345","service":"twitter"}`, string(b))
}

func TestUserCheckGithub(t *testing.T) {
	EnableServices("github")
	defer DisableServices()
	clock := newClock()
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	kid := key.ID()
	usr, err := NewUserForSigning(kid, "github", "gabriel")
	require.NoError(t, err)
	msg, err := usr.Sign(key.SignKey())
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	// t.Logf("Message:\n%s", msg)

	sc := GenerateSigchain(key, clock.Now())
	stu, err := NewUser(kid, "github", "gabriel", "https://gist.github.com/gabriel/19f95cf0bbe03171815790d497a44ec3", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, stu, key.SignKey(), clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	_, err = GenerateUserStatement(sc, stu, key.SignKey(), clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	usrs, err := UserCheck(context.TODO(), sc, nil, clock.Now)
	require.NoError(t, err)
	require.Equal(t, 1, len(usrs))
	require.Equal(t, "github", usrs[0].Service)
	require.Equal(t, "gabriel", usrs[0].Name)
	require.Equal(t, TimeFromMillis(1234567890004), usrs[0].CheckedAt)

	// Check with updated sigchain with different user

	// usr, err = NewUserForSigning(kid, "github", "gabriel2")
	// require.NoError(t, err)
	// msg, err = usr.Sign(key.SignKey())
	// require.NoError(t, err)
	// require.NotEqual(t, "", msg)
	// t.Logf("Message:\n%s", msg)
	// https://gist.github.com/gabriel/f229c4965d95d1348b9d047851bf76e5
	// has signed message for github,gabriel2
	usr2, err := NewUser(kid, "github", "gabriel", "https://gist.github.com/gabriel/f229c4965d95d1348b9d047851bf76e5", 1)
	require.NoError(t, err)
	b2, err := json.Marshal(usr2)
	require.NoError(t, err)
	st2, err := GenerateStatement(sc, b2, key.SignKey(), "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	usrs, err = UserCheck(context.TODO(), sc, nil, clock.Now)
	require.EqualError(t, err, "name mismatch gabriel != gabriel2")
	require.Equal(t, 0, len(usrs))

	_, err = sc.Revoke(st2.Seq, key.SignKey())
	require.NoError(t, err)

	// Check with updated sigchain with different service

	// usr = &User{KID: kid, Service: "github2", Name: "gabriel"}
	// msg, err = usr.Sign(key.SignKey())
	// require.NoError(t, err)
	// require.NotEqual(t, "", msg)
	// t.Logf("Message:\n%s", msg)
	// https://gist.github.com/gabriel/cb842128916034c630907cb04216795f
	// has signed message for github2,gabriel
	usr3, err := NewUser(kid, "github", "gabriel", "https://gist.github.com/gabriel/cb842128916034c630907cb04216795f", 1)
	require.NoError(t, err)
	b3, err := json.Marshal(usr3)
	require.NoError(t, err)
	st3, err := GenerateStatement(sc, b3, key.SignKey(), "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st3)
	require.NoError(t, err)

	usr4, err := UserCheck(context.TODO(), sc, nil, clock.Now)
	require.EqualError(t, err, "service mismatch github != github2")
	require.Nil(t, usr4)

	_, err = sc.Revoke(st3.Seq, key.SignKey())
	require.NoError(t, err)

	// Empty sigchain
	sc5 := NewSigchain(key.PublicKey().SignPublicKey())
	stu5, err := NewUser(kid, "github", "gabriel", "https://gist.github.com/gabriel/19f95cf0bbe03171815790d497a44ec3", sc5.LastSeq()+1)
	require.NoError(t, err)
	st5, err := GenerateUserStatement(sc5, stu5, key.SignKey(), clock.Now())
	require.NoError(t, err)
	err = sc5.Add(st5)
	require.NoError(t, err)

	usrs, err = UserCheck(context.TODO(), sc5, nil, clock.Now)
	require.NoError(t, err)
	require.Equal(t, 1, len(usrs))
	require.Equal(t, "github", usrs[0].Service)
	require.Equal(t, "gabriel", usrs[0].Name)
}

func TestCheckNoUser(t *testing.T) {
	key := GenerateKey()
	sc := NewSigchain(key.PublicKey().SignPublicKey())
	req := NewHTTPRequestor()
	clock := newClock()

	usrs, err := UserCheck(context.TODO(), sc, req, clock.Now)
	require.NoError(t, err)
	require.Equal(t, 0, len(usrs))
}

func TestRequestTwitter(t *testing.T) {
	EnableServices("twitter")
	defer DisableServices()
	surl := "https://twitter.com/boboloblaw/status/1202714310025236481"
	u, err := url.Parse(surl)
	require.NoError(t, err)
	req := NewHTTPRequestor()
	body, err := req.RequestURL(context.TODO(), u)
	require.NoError(t, err)

	msg, err := findStringInHTML(string(body))
	require.NoError(t, err)

	t.Logf(msg)
	s, err := trimHTML(msg)
	require.NoError(t, err)
	expected := `eb90A0en2hcwfYijYDez0uArQs3HYgOiJlOgVUIfSeipsu7JJcO6819zwug6n9639e2e18gwZtMCQlePtNVn9wTCKqLPKyEa7sfoHfnVB0hPvyKMbyjBGqHh7dz327KuwGT7OwwkMEmgjibmwuK6N31UwmaFLcDXRyz4c7NV5uSV1Msu2KjbMiH1JUIqH80eo7ux6O3uRXcb5ShhfqMJx`
	require.Equal(t, expected, s)
}

func TestVerifyUser(t *testing.T) {
	EnableServices("github")
	defer DisableServices()
	key := GenerateKey()
	kid := key.ID()
	spk := key.PublicKey().SignPublicKey()

	u, uerr := NewUserForSigning(kid, "github", "gabriel")
	require.NoError(t, uerr)
	require.NotNil(t, u)

	msg, err := u.Sign(key.SignKey())
	require.NoError(t, err)

	uout, err := VerifyUser(msg, spk, nil)
	require.NoError(t, err)

	require.Equal(t, "gabriel", uout.Name)
	require.Equal(t, "github", uout.Service)
	require.Equal(t, kid, uout.KID)

	_, err = VerifyUser(msg, spk, uout)
	require.NoError(t, err)
}

func TestNewUser(t *testing.T) {
	EnableServices("github", "twitter")
	defer DisableServices()
	key := GenerateKey()
	kid := key.ID()

	u, uerr := NewUser(kid, "github", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u)

	u2, uerr := NewUser(kid, "github", "gabriel", "https://gist.githb.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid host for url https://gist.githb.com/gabriel/deadbeef")
	require.Nil(t, u2)

	u3, uerr := NewUser(kid, "github", "gabriel", "http://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid scheme for url http://gist.github.com/gabriel/deadbeef")
	require.Nil(t, u3)

	u4, uerr := NewUser(kid, "github", "gabriel", "https://gist.github.com/gabril/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabril != gabriel")
	require.Nil(t, u4)

	u5, uerr := NewUser(kid, "github", "gabriel", "https://gist.github.com/gabriel", 1)
	require.EqualError(t, uerr, "path invalid [gabriel] for url https://gist.github.com/gabriel")
	require.Nil(t, u5)

	u6, uerr := NewUser(kid, "github", "gab", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabriel != gab")
	require.Nil(t, u6)

	u7, uerr := NewUser(kid, "git", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid service git")
	require.Nil(t, u7)

	u8, uerr := NewUser(kid, "github", "", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "name is empty")
	require.Nil(t, u8)

	u9, uerr := NewUser(kid, "twitter", "@gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u9)
	require.Equal(t, "gbrltest", u9.Name)

	u10, uerr0 := NewUser(kid, "twitter", "Gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr0, "user name should be lowercase")
	require.Nil(t, u10)

	u11, uerr1 := NewUser(kid, "twitter", "gbrltest🤓", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr1, "user name has non-ASCII characters")
	require.Nil(t, u11)

	u12, uerr := NewUser(kid, "twitter", "gbrltest", "twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr, "invalid scheme for url twitter.com/gbrltest/status/1234")
	require.Nil(t, u12)
}
