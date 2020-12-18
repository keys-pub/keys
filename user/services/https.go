package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/http"
	"github.com/pkg/errors"
)

type https struct{}

// HTTPS service.
var HTTPS = &https{}

func (s *https) ID() string {
	return "https"
}

func (s *https) NormalizeName(name string) string {
	name = strings.ToLower(name)
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

	if regexIP.MatchString(name) {
		return errors.Errorf("not a valid domain name")
	}

	return nil
}

func (s *https) NormalizeURL(name string, urs string) (string, error) {
	return basicURLString(strings.ToLower(urs))
}

func (s *https) ValidateURL(name string, urs string) (string, error) {
	if err := s.ValidateName(name); err != nil {
		return "", errors.Wrapf(err, "invalid url")
	}

	matches := []string{
		fmt.Sprintf("https://%s/keyspub.txt", name),
		fmt.Sprintf("https://%s/.well-known/keyspub.txt", name),
	}

	for _, m := range matches {
		if urs == m {
			return urs, nil
		}
	}

	return "", errors.Errorf("invalid url: %s", urs)
}

func (s *https) CheckContent(name string, b []byte) ([]byte, error) {
	return b, nil
}

func (s *https) Request(ctx context.Context, client http.Client, urs string) ([]byte, error) {
	req, err := http.NewRequest("GET", urs, nil)
	if err != nil {
		return nil, err
	}
	b, err := client.Request(ctx, req, nil)
	if err != nil {
		if errHTTP, ok := errors.Cause(err).(http.ErrHTTP); ok && errHTTP.StatusCode == 404 {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

var regexIP = regexp.MustCompile(`^[0-9].*\.[0-9].*\.[0-9].*\.[0-9].*$`)

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