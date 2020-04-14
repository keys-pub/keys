package util_test

import (
	"testing"

	"github.com/keys-pub/keys/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

type testRetry struct {
	attempt int
	wrap    bool
}

func (t *testRetry) fn() error {
	t.attempt = t.attempt + 1
	if t.attempt == 1 {
		if t.wrap {
			return errors.Wrapf(&errTest{}, "failed on attempt %d", t.attempt)
		}
		return &errTest{}
	}
	return nil
}

func TestRetryEDefault(t *testing.T) {
	tr := &testRetry{}
	err := util.RetryE(tr.fn)
	require.NoError(t, err)
}

func TestRetryError(t *testing.T) {
	err := util.RetryE(func() error {
		return errors.Errorf("error")
	})
	require.Error(t, err)
}

func TestRetrySError(t *testing.T) {
	_, err := util.RetrySE(func() (string, error) {
		return "", errors.Errorf("error")
	})
	require.Error(t, err)
}

func TestRetryEWrap(t *testing.T) {
	tr := &testRetry{wrap: true}
	err := util.RetryE(tr.fn)
	require.NoError(t, err)
}
