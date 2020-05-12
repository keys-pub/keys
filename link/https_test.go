package link_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys/link"
	"github.com/stretchr/testify/require"
)

func TestHTTPSNormalizeName(t *testing.T) {
	name := link.HTTPS.NormalizeName("Keys.pub")
	require.Equal(t, "keys.pub", name)
}

func TestHTTPSValidateName(t *testing.T) {
	err := link.HTTPS.ValidateName("keys.pub")
	require.NoError(t, err)

	err = link.HTTPS.ValidateName("keys.co.uk")
	require.NoError(t, err)

	err = link.HTTPS.ValidateName("g.co")
	require.NoError(t, err)

	err = link.HTTPS.ValidateName("o-k.co")
	require.NoError(t, err)

	err = link.HTTPS.ValidateName("llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk")
	require.NoError(t, err)

	err = link.HTTPS.ValidateName("keys.pub/test")
	require.EqualError(t, err, "not a valid domain name")

	err = link.HTTPS.ValidateName(`keys.pub\/test`)
	require.EqualError(t, err, "not a valid domain name")

	err = link.HTTPS.ValidateName(`Keys.Pub`)
	require.EqualError(t, err, "name should be lowercase")

	b := bytes.Repeat([]byte{byte('a')}, 256)
	err = link.HTTPS.ValidateName(string(b) + ".com")
	require.EqualError(t, err, "name is too long")

	err = link.HTTPS.ValidateName("-foo.com")
	require.EqualError(t, err, "not a valid domain name")

	err = link.HTTPS.ValidateName("127.0.0.1")
	require.EqualError(t, err, "not a valid domain name")

	err = link.HTTPS.ValidateName("127.127.127.127")
	require.EqualError(t, err, "not a valid domain name")

	err = link.HTTPS.ValidateName("1:2:3:4:5:6:7:8")
	require.EqualError(t, err, "not a valid domain name")

	err = link.HTTPS.ValidateName("::255.255.255.255")
	require.EqualError(t, err, "not a valid domain name")
}

func TestHTTPSValidateURL(t *testing.T) {
	testValidateURL(t, link.HTTPS,
		"keys.pub",
		"https://keys.pub/keyspub.txt",
		"https://keys.pub/keyspub.txt")

	testValidateURLErr(t, link.HTTPS,
		"keys.pub",
		"https://keys.pub/foo.txt",
		"invalid url: https://keys.pub/foo.txt")

	testValidateURLErr(t, link.HTTPS,
		"keys.pub",
		"https://keys.pubb/keyspub.txt",
		"invalid url: https://keys.pubb/keyspub.txt")

	testValidateURLErr(t, link.HTTPS,
		"keys.pub",
		"http://keys.pub/keyspub.txt",
		"invalid url: http://keys.pub/keyspub.txt")

	testValidateURLErr(t, link.HTTPS,
		"keys.pub",
		"http:///keyspub.txt",
		"invalid url: http:///keyspub.txt")

	testValidateURLErr(t, link.HTTPS,
		"keys.pub/test/",
		"http://keys.pub/test/keyspub.txt",
		"invalid url: http://keys.pub/test/keyspub.txt")
}
