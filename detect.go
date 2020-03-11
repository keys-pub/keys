package keys

import (
	"strings"
	"unicode/utf8"
)

type DataType = string

const (
	// UnknownType is unknown
	UnknownType DataType = ""
	// IDType is string identifier (keys.ID)
	IDType DataType = "id"
	// SaltpackType is armored saltpack encoding.
	SaltpackArmoredType DataType = "saltpack-armored"
	// SaltpackType is binary saltpack encoding.
	// SaltpackType DataType = "saltpack"
)

// DetectDataType tries to find out what data type the bytes are.
func DetectDataType(b []byte) DataType {
	if utf8.Valid(b) {
		s := string(b)
		if _, err := ParseID(s); err == nil {
			return IDType
		} else if len(s) < 100 && (strings.HasPrefix(s, "kex1") || strings.HasPrefix(s, "kbx1")) {
			return IDType
		}

		if strings.Contains(s, "BEGIN ") || strings.Contains(s, " MESSAGE.") {
			return SaltpackArmoredType
		}
	}

	// TODO: SaltpackType

	return UnknownType

}
