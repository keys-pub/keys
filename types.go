package keys

const (
	// SecretKeyType is a nacl.secretbox compabile secret key.
	SecretKeyType string = "secret-key"
	// SignKeyType is a nacl.sign compatible sign key.
	SignKeyType string = "sign-key"
	// SignPublicKeyType is the public key part of sign key (pair).
	SignPublicKeyType string = "sign-public-key"
	// BoxKeyType is the nacl.box compatible public/private key.
	BoxKeyType string = "box-key"
	// BoxPublicKeyType is the public key part of a nacl.box compatible key.
	BoxPublicKeyType string = "box-public-key"
	// CertificateKeyType is the private key for a certificate.
	CertificateKeyType string = "cert-key"
	// CertificatePublicKeyType is the public PEM encoded certificate.
	CertificatePublicKeyType string = "cert-public-key"
	// PassphraseType is a string passphrase on any length.
	PassphraseType string = "passphrase"
	// KeyType is the type for a Key.
	KeyType string = "key"
	// PublicKeyType is the type for a PublicKey.
	PublicKeyType string = "public-key"
	// SigchainType is a the type for a Sigchain.
	SigchainType string = "sigchain"
)

// TypeDescription is the description for a type string.
func TypeDescription(typ string) string {
	switch typ {
	case SecretKeyType:
		return "secret key"
	case SignKeyType:
		return "sign key"
	case SignPublicKeyType:
		return "sign public key"
	case BoxKeyType:
		return "box key"
	case BoxPublicKeyType:
		return "box public key"
	case CertificateKeyType:
		return "certificate key"
	case CertificatePublicKeyType:
		return "certificate public key"
	case PassphraseType:
		return "passphrase"
	case KeyType:
		return "key"
	case PublicKeyType:
		return "public key"
	case SigchainType:
		return "sigchain"
	default:
		return "unknown item"
	}
}
