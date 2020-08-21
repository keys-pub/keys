package json_test

import (
	"testing"

	"github.com/keys-pub/keys/json"
	"github.com/stretchr/testify/require"
)

func TestMarshal(t *testing.T) {
	b, err := json.Marshal(
		json.String("key1", "val1"),
		json.Int("key2", 2),
	)
	require.NoError(t, err)
	require.Equal(t, `{"key1":"val1","key2":2}`, string(b))

	_, err = json.Marshal(
		json.String(`"`, ""),
	)
	require.EqualError(t, err, "invalid character in key")
	_, err = json.Marshal(
		json.String("key1", `"`),
	)
	require.EqualError(t, err, "invalid character in value")
}
