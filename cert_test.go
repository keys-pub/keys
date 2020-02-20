package keys_test

import (
	"crypto/x509"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestGenerateCertificateKey(t *testing.T) {
	caCert, err := keys.GenerateCertificateKey("localhost", true, nil)
	require.NoError(t, err)
	require.True(t, len(caCert.Public()) > 0)
	require.True(t, len(caCert.Private()) > 0)

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(caCert.Public()))
	if !ok {
		t.Fatal("failed to add to cert pool")
	}

	// TODO: Generated cert fails to verify
	// xcaCert, xerr := caCert.X509Certificate()
	// require.NoError(t, xerr)

	// cert, certErr := GenerateCertificateKey("localhost", false, xcaCert)
	// require.NoError(t, certErr)

	xcert, err := caCert.X509Certificate()
	require.NoError(t, err)
	_, err = xcert.Verify(x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   certPool,
	})
	require.NoError(t, err)

	certKey, err := keys.NewCertificateKey(caCert.Private(), caCert.Public())
	require.NoError(t, err)
	require.NotNil(t, certKey)
}

func TestCertificateKey(t *testing.T) {
	public := `-----BEGIN CERTIFICATE-----
MIIBbDCCARKgAwIBAgIQI3ViQTyP8XxlaXUnwbKORjAKBggqhkjOPQQDAjAQMQ4w
DAYDVQQKEwVLZXl1cDAeFw0xOTA3MjQwMjAwMTZaFw0yOTA3MjEwMjAwMTZaMBAx
DjAMBgNVBAoTBUtleXVwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOXhT88Pe
/Ql5LFyxYUb9a0v+HOKqs2PGO/0CE4UPSj5XpocMUotMSm4Yau1/1j1SV+/Vktin
ixCC7hfVyswyFqNOMEwwDgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MAoGCCqG
SM49BAMCA0gAMEUCIQDyOYbe6kzrU8Z45/KmkYX3fzfDAvjq3vqSUe5Xaf/KwQIg
CmvKhhT2XYwfNim1eLnU78spAetAyk//C7w+BfxgnPo=
-----END CERTIFICATE-----`
	private := `-----BEGIN ECDSA PRIVATE KEY-----
MHcCAQEEIPflp/bXqmjd6AvkzfsGd2q1F+wjlJ8rVL1TEYYl3giVoAoGCCqGSM49
AwEHoUQDQgAEOXhT88Pe/Ql5LFyxYUb9a0v+HOKqs2PGO/0CE4UPSj5XpocMUotM
Sm4Yau1/1j1SV+/VktinixCC7hfVyswyFg==
-----END ECDSA PRIVATE KEY-----`

	certKey, err := keys.NewCertificateKey(private, public)
	require.NoError(t, err)
	require.NotNil(t, certKey)

}
