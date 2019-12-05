package saltpack

import (
	"testing"
)

func TestSigncrypt(t *testing.T) {
	testEncrypt(t, SigncryptMode)
}

func TestSigncryptStream(t *testing.T) {
	testEncryptStream(t, SigncryptMode)
}

func TestSigncryptOpenError(t *testing.T) {
	testOpenError(t, SigncryptMode)
}
