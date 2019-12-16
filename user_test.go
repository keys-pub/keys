package keys

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewUserForTwitterSigning(t *testing.T) {
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	req := NewMockRequestor()
	clock := newClock()
	uc := NewTestUserContext(req, clock.Now)
	user, err := NewUserForSigning(uc, key.ID(), "twitter", "123456789012345")
	require.NoError(t, err)
	msg, err := user.Sign(key.SignKey())
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	t.Logf("Length: %d", len(msg))
	require.False(t, len(msg) > 280)
}

func TestNewUserMarshal(t *testing.T) {
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	kid := key.ID()
	req := NewMockRequestor()
	clock := newClock()
	uc := NewTestUserContext(req, clock.Now)
	user, err := NewUser(uc, kid, "twitter", "123456789012345", "https://twitter.com/123456789012345/status/1234567890", 1)
	require.NoError(t, err)
	b, err := json.Marshal(user)
	require.NoError(t, err)
	require.Equal(t, `{"kid":"HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec","name":"123456789012345","seq":1,"service":"twitter","url":"https://twitter.com/123456789012345/status/1234567890"}`, string(b))

	var userOut User
	err = json.Unmarshal(b, &userOut)
	require.NoError(t, err)
	require.Equal(t, user.Name, userOut.Name)
	require.Equal(t, user.Seq, userOut.Seq)
	require.Equal(t, user.KID, userOut.KID)
	require.Equal(t, user.Service, userOut.Service)
	require.Equal(t, user.URL, userOut.URL)

	user, err = NewUserForSigning(uc, kid, "twitter", "123456789012345")
	require.NoError(t, err)
	b, err = json.Marshal(user)
	require.NoError(t, err)
	require.Equal(t, `{"kid":"HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec","name":"123456789012345","service":"twitter"}`, string(b))
}

func TestUserCheckGithub(t *testing.T) {
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	kid := key.ID()

	clock := newClock()
	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)

	err = req.SetResponseFile("https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", "testdata/github/70281cc427850c272a8574af4d8564d9")
	require.NoError(t, err)

	user, err := NewUserForSigning(uc, kid, "github", "alice")
	require.NoError(t, err)
	msg, err := user.Sign(key.SignKey())
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	// t.Logf("Message:\n%s", msg)

	sc := GenerateSigchain(key, clock.Now())
	stu, err := NewUser(uc, kid, "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, stu, key.SignKey(), clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	_, err = GenerateUserStatement(sc, stu, key.SignKey(), clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	users, err := uc.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Equal(t, 1, len(users))
	require.Equal(t, "github", users[0].User.Service)
	require.Equal(t, "alice", users[0].User.Name)
	require.Equal(t, TimeFromMillis(1234567890005), users[0].VerifiedAt)
	require.Equal(t, TimeFromMillis(1234567890004), users[0].Timestamp)
}

func TestUserCheckGithubWrongName(t *testing.T) {
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	kid := key.ID()

	clock := newClock()
	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)

	// user, err = NewUserForSigning(uc, kid, "github", "alice2")
	// require.NoError(t, err)
	// msg, err = user.Sign(key.SignKey())
	// require.NoError(t, err)
	// require.NotEqual(t, "", msg)
	// t.Logf("Message:\n%s", msg)
	sc := GenerateSigchain(key, clock.Now())
	err = req.SetResponseFile("https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", "testdata/github/a7b1370270e2672d4ae88fa5d0c6ade7")
	require.NoError(t, err)
	user2, err := NewUser(uc, kid, "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	b2, err := json.Marshal(user2)
	require.NoError(t, err)
	st2, err := GenerateStatement(sc, b2, key.SignKey(), "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	users, err := uc.CheckSigchain(context.TODO(), sc)
	require.Equal(t, 1, len(users))
	require.Equal(t, UserStatusFailure, users[0].Status)
	require.Equal(t, users[0].Err, "name mismatch alice != alice2")
}

func TestUserCheckGithubWrongService(t *testing.T) {
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	kid := key.ID()

	clock := newClock()
	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)
	sc := GenerateSigchain(key, clock.Now())

	// user = &User{KID: kid, Service: "github2", Name: "gabriel"}
	// msg, err = user.Sign(key.SignKey())
	// require.NoError(t, err)
	// require.NotEqual(t, "", msg)
	// t.Logf("Message:\n%s", msg)
	err = req.SetResponseFile("https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", "testdata/github/bd679134acba688cbcc0a65fa0890d76")
	require.NoError(t, err)
	user, err := NewUser(uc, kid, "github", "alice", "https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", 1)
	require.NoError(t, err)
	b, err := json.Marshal(user)
	require.NoError(t, err)
	st, err := GenerateStatement(sc, b, key.SignKey(), "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	users, err := uc.CheckSigchain(context.TODO(), sc)
	require.Equal(t, 1, len(users))
	require.Equal(t, UserStatusFailure, users[0].Status)
	require.Equal(t, users[0].Err, "service mismatch github != github2")
}

func TestUserCheckTwitter(t *testing.T) {
	key, err := NewKeyFromSeedPhrase(bobSeed, false)
	require.NoError(t, err)
	kid := key.ID()

	clock := newClock()
	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)

	user, err := NewUserForSigning(uc, kid, "twitter", "bob")
	require.NoError(t, err)
	msg, err := user.Sign(key.SignKey())
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	t.Logf("Message:\n%s", msg)

	sc := GenerateSigchain(key, clock.Now())
	stu, err := NewUser(uc, kid, "twitter", "bob", "https://twitter.com/bob/status/1205589994380783616", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, stu, key.SignKey(), clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	_, err = GenerateUserStatement(sc, stu, key.SignKey(), clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	err = req.SetResponseFile("https://twitter.com/bob/status/1205589994380783616", "testdata/twitter/1205589994380783616")
	require.NoError(t, err)

	users, err := uc.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Equal(t, 1, len(users))
	require.NotNil(t, users[0].User)
	require.Equal(t, "twitter", users[0].User.Service)
	require.Equal(t, "bob", users[0].User.Name)
	require.Equal(t, TimeFromMillis(1234567890005), users[0].VerifiedAt)
	require.Equal(t, TimeFromMillis(1234567890004), users[0].Timestamp)
}

func TestCheckNoUser(t *testing.T) {
	key := GenerateKey()
	sc := NewSigchain(key.PublicKey().SignPublicKey())

	req := NewMockRequestor()
	clock := newClock()
	uc := NewTestUserContext(req, clock.Now)

	users, err := uc.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Equal(t, 0, len(users))
}

func TestVerifyUser(t *testing.T) {
	key := GenerateKey()
	kid := key.ID()
	spk := key.PublicKey().SignPublicKey()

	req := NewMockRequestor()
	clock := newClock()
	uc := NewTestUserContext(req, clock.Now)

	u, uerr := NewUserForSigning(uc, kid, "github", "gabriel")
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
	key := GenerateKey()
	kid := key.ID()
	uc := NewDefaultUserContext()

	u, uerr := NewUser(uc, kid, "github", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u)

	u2, uerr := NewUser(uc, kid, "github", "gabriel", "https://gist.githb.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid host for url https://gist.githb.com/gabriel/deadbeef")
	require.Nil(t, u2)

	u3, uerr := NewUser(uc, kid, "github", "gabriel", "http://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid scheme for url http://gist.github.com/gabriel/deadbeef")
	require.Nil(t, u3)

	u4, uerr := NewUser(uc, kid, "github", "gabriel", "https://gist.github.com/gabril/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabril != gabriel")
	require.Nil(t, u4)

	u5, uerr := NewUser(uc, kid, "github", "gabriel", "https://gist.github.com/gabriel", 1)
	require.EqualError(t, uerr, "path invalid [gabriel] for url https://gist.github.com/gabriel")
	require.Nil(t, u5)

	u6, uerr := NewUser(uc, kid, "github", "gab", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabriel != gab")
	require.Nil(t, u6)

	u7, uerr := NewUser(uc, kid, "git", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid service git")
	require.Nil(t, u7)

	u8, uerr := NewUser(uc, kid, "github", "", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "name is empty")
	require.Nil(t, u8)

	u9, uerr := NewUser(uc, kid, "twitter", "@gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u9)
	require.Equal(t, "gbrltest", u9.Name)

	u10, uerr0 := NewUser(uc, kid, "twitter", "Gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr0, "user name should be lowercase")
	require.Nil(t, u10)

	u11, uerr1 := NewUser(uc, kid, "twitter", "gbrltest🤓", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr1, "user name has non-ASCII characters")
	require.Nil(t, u11)

	u12, uerr := NewUser(uc, kid, "twitter", "gbrltest", "twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr, "invalid scheme for url twitter.com/gbrltest/status/1234")
	require.Nil(t, u12)
}
