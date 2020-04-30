package link

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

type https struct{}

// HTTPS service.
var HTTPS = &https{}

func (s *https) Name() string {
	return "https"
}

func (s *https) NormalizeName(name string) string {
	return name
}

func (s *https) ValidateName(name string) error {
	isASCII := encoding.IsASCII([]byte(name))
	if !isASCII {
		return errors.Errorf("name has non-ASCII characters")
	}
	hu := encoding.HasUpper(name)
	if hu {
		return errors.Errorf("name should be lowercase")
	}
	if len(name) > 256 {
		return errors.Errorf("name is too long")
	}

	if !isValidHostname(name) {
		return errors.Errorf("not a valid domain name")
	}

	return nil
}

func (s *https) ValidateURL(name string, u *url.URL) (*url.URL, error) {
	if u.String() != fmt.Sprintf("https://%s/keyspub.txt", name) {
		return nil, errors.Errorf("invalid url: %s", u.String())
	}
	return url.Parse(fmt.Sprintf("https://%s/keyspub.txt", name))
}

func (s *https) CheckContent(name string, b []byte) ([]byte, error) {
	return b, nil
}

// From github.com/keybase/client/libkb/util.go
// Found regex here: http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
var regexHostname = regexp.MustCompile("^(?i:[a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])$")

func isValidHostname(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !regexHostname.MatchString(p) {
			return false
		}
	}
	// TLDs must be >=2 chars
	return len(parts[len(parts)-1]) >= 2
}
