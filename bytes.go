package keys

// Bytes64 converts byte slice to *[64]byte or panics.
func Bytes64(b []byte) *[64]byte {
	if len(b) != 64 {
		panic("not 64 bytes")
	}
	var b64 [64]byte
	copy(b64[:], b)
	return &b64
}

// Bytes32 converts byte slice to *[32]byte or panics.
func Bytes32(b []byte) *[32]byte {
	if len(b) != 32 {
		panic("not 32 bytes")
	}
	var b32 [32]byte
	copy(b32[:], b)
	return &b32
}

// Bytes24 converts byte slice to *[24]byte or panics.
func Bytes24(b []byte) *[24]byte {
	if len(b) != 24 {
		panic("not 24 bytes")
	}
	var b24 [24]byte
	copy(b24[:], b)
	return &b24
}

// Bytes16 converts byte slice to *[16]byte or panics.
func Bytes16(b []byte) *[16]byte {
	if len(b) != 16 {
		panic("not 16 bytes")
	}
	var b16 [16]byte
	copy(b16[:], b)
	return &b16
}
