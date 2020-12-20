package user

import (
	"fmt"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

// FindVerify finds and verifies content in bytes.
func FindVerify(usr *User, b []byte, isHTML bool) (Status, string, error) {
	msg, _ := encoding.FindSaltpack(string(b), isHTML)
	if msg == "" {
		logger.Warningf("User statement content not found")
		return StatusContentNotFound, "", errors.Errorf("user signed message content not found")
	}

	verifyMsg := fmt.Sprintf("BEGIN MESSAGE.\n%s\nEND MESSAGE.", msg)
	if err := usr.Verify(verifyMsg); err != nil {
		logger.Warningf("Failed to verify statement: %s", err)
		return StatusStatementInvalid, "", err
	}

	return StatusOK, verifyMsg, nil
}
