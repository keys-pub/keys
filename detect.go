package keys

import (
	"strings"
	"unicode/utf8"
)

// DataType is the type of key data.
type DataType = string

const (
	// UnknownType is unknown
	UnknownType DataType = ""
	// IDType is string identifier (keys.ID)
	IDType DataType = "id"

	// SaltpackArmoredType is armored saltpack encoding.
	SaltpackArmoredType DataType = "saltpack-armored"
	// SaltpackType is binary saltpack encoding.
	// SaltpackType DataType = "saltpack"

	// SSHPublicType is ssh public key "ssh-ed25519 AAAAC3Nz..."
	SSHPublicType DataType = "ssh-public"
	// SSHType is ssh private key "-----BEGIN OPENSSH PRIVATE..."
	SSHType DataType = "ssh"
)

// DetectDataType tries to find out what data type the bytes are.
// Returns bytes which may be different from input (for example, if whitespace is stripped).
func DetectDataType(b []byte) ([]byte, DataType) {
	if !utf8.Valid(b) {
		return b, UnknownType
	}

	s := strings.TrimSpace(string(b))

	typ := UnknownType

	if _, err := ParseID(s); err == nil {
		typ = IDType
	} else if len(s) < 100 && (strings.HasPrefix(s, "kex1") || strings.HasPrefix(s, "kbx1")) {
		typ = IDType
	} else if strings.Contains(s, "BEGIN ") && strings.Contains(s, " MESSAGE") {
		typ = SaltpackArmoredType
	} else if strings.HasPrefix(s, "-----BEGIN ") {
		typ = SSHType
	} else if strings.HasPrefix(s, "ssh-") {
		typ = SSHPublicType
	}

	return []byte(s), typ

}
