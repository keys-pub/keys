package link_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func TestHTTPSNormalizeName(t *testing.T) {
	https := link.NewHTTPS()
	name := https.NormalizeName("Keys.pub")
	require.Equal(t, "keys.pub", name)
}

func TestHTTPSValidateName(t *testing.T) {
	var err error
	https := link.NewHTTPS()

	err = https.ValidateName("keys.pub")
	require.NoError(t, err)

	err = https.ValidateName("keys.co.uk")
	require.NoError(t, err)

	err = https.ValidateName("g.co")
	require.NoError(t, err)

	err = https.ValidateName("o-k.co")
	require.NoError(t, err)

	err = https.ValidateName("llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk")
	require.NoError(t, err)

	err = https.ValidateName("keys.pub ")
	require.EqualError(t, err, "not a valid domain name")

	err = https.ValidateName("keys.pub/test")
	require.EqualError(t, err, "not a valid domain name")

	err = https.ValidateName(`keys.pub\/test`)
	require.EqualError(t, err, "not a valid domain name")

	err = https.ValidateName(`Keys.Pub`)
	require.EqualError(t, err, "name should be lowercase")

	b := bytes.Repeat([]byte{byte('a')}, 256)
	err = https.ValidateName(string(b) + ".com")
	require.EqualError(t, err, "name is too long")

	err = https.ValidateName("-foo.com")
	require.EqualError(t, err, "not a valid domain name")

	err = https.ValidateName("127.0.0.1")
	require.EqualError(t, err, "not a valid domain name")

	err = https.ValidateName("127.127.127.127")
	require.EqualError(t, err, "not a valid domain name")

	err = https.ValidateName("1:2:3:4:5:6:7:8")
	require.EqualError(t, err, "not a valid domain name")

	err = https.ValidateName("::255.255.255.255")
	require.EqualError(t, err, "not a valid domain name")
}

func TestHTTPSValidateURL(t *testing.T) {
	https := link.NewHTTPS()
	testValidateURL(t, https,
		"keys.pub",
		"https://keys.pub/keyspub.txt",
		"https://keys.pub/keyspub.txt")

	testValidateURL(t, https,
		"keys.pub",
		"https://keys.pub/.well-known/keyspub.txt",
		"https://keys.pub/.well-known/keyspub.txt")

	testValidateURLErr(t, https,
		"keys.pub ",
		"https://keys.pub /keyspub.txt",
		"invalid url: not a valid domain name")

	testValidateURLErr(t, https,
		"keys.pub",
		"https://keys.pub/foo.txt",
		"invalid url: https://keys.pub/foo.txt")

	testValidateURLErr(t, https,
		"keys.pub",
		"https://keys.pubb/keyspub.txt",
		"invalid url: https://keys.pubb/keyspub.txt")

	testValidateURLErr(t, https,
		"keys.pub",
		"http://keys.pub/keyspub.txt",
		"invalid url: http://keys.pub/keyspub.txt")

	testValidateURLErr(t, https,
		"keys.pub",
		"http:///keyspub.txt",
		"invalid url: http:///keyspub.txt")

	testValidateURLErr(t, https,
		"keys.pub/test/",
		"http://keys.pub/test/keyspub.txt",
		"invalid url: not a valid domain name")
}
