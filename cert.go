package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

// CertificateKey with is a PEM encoded X.509v3 certificate (public key) and a PEM encoded EC private key.
type CertificateKey struct {
	private string // PEM encoded EC private key ASN.1, DER format
	public  string // PEM encoded X.509v3 certificate
	tlsCert tls.Certificate
}

// NewCertificateKey from PEM encoded X.509v3 certificate data and PEM encoded EC private key ASN.1, DER format
func NewCertificateKey(private string, public string) (*CertificateKey, error) {
	tlsCert, err := tls.X509KeyPair([]byte(public), []byte(private))
	if err != nil {
		return nil, err
	}
	return &CertificateKey{
		private: private,
		public:  public,
		tlsCert: tlsCert,
	}, nil
}

// Private returns a PEM encoded EC private key ASN.1, DER format.
func (c CertificateKey) Private() string {
	return c.private
}

// Public returns a PEM encoded X.509v3 certificate.
func (c CertificateKey) Public() string {
	return c.public
}

// TLSCertificate returns a tls.Certificate.
func (c CertificateKey) TLSCertificate() tls.Certificate {
	return c.tlsCert
}

// X509Certificate returns a x509.Certificate.
func (c CertificateKey) X509Certificate() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(c.public))
	if block == nil {
		return nil, errors.Errorf("failed to parse certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// GenerateCertificateKey creates a certificate key.
func GenerateCertificateKey(commonName string, isCA bool, parent *x509.Certificate) (*CertificateKey, error) {
	if commonName == "" {
		return nil, errors.Errorf("failed to generate certificate: no common name specified")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate ecdsa key")
	}
	// TODO: Regen on expiration
	validFor := 365 * 24 * time.Hour * 10
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate serial number")
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{commonName},
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}
	if parent == nil {
		parent = &template
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, extractPublicKey(priv), priv)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create x509 certificate")
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal x509 private key")
	}
	// privBytes := x509.MarshalPKCS1PrivateKey(priv)
	// key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	key := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: privBytes})
	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return NewCertificateKey(string(key), string(certData))
}

func extractPublicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
