package saltpack

import (
	"bufio"
	"io"
	"os"
	"strings"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// Sign ...
func Sign(b []byte, armored bool, key *keys.EdX25519Key) ([]byte, error) {
	if armored {
		s, err := ksaltpack.SignArmor62(ksaltpack.Version2(), b, newSignKey(key), "")
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return ksaltpack.Sign(ksaltpack.Version2(), b, newSignKey(key))
}

// SignDetached ...
func SignDetached(b []byte, armored bool, key *keys.EdX25519Key) ([]byte, error) {
	if armored {
		s, err := ksaltpack.SignDetachedArmor62(ksaltpack.Version2(), b, newSignKey(key), "")
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return ksaltpack.SignDetached(ksaltpack.Version2(), b, newSignKey(key))
}

// Verify ...
func Verify(b []byte) ([]byte, keys.ID, error) {
	s := &saltpack{}
	var spk ksaltpack.SigningPublicKey
	var out []byte
	var err error
	enc, armored := detectSign(b)
	switch enc {
	case SignEncoding:
		if armored {
			spk, out, _, err = ksaltpack.Dearmor62Verify(signVersionValidator, string(b), s)
		} else {
			spk, out, err = ksaltpack.Verify(signVersionValidator, b, s)
		}
	default:
		return nil, "", errors.Errorf("invalid data")
	}
	if err != nil {
		return nil, "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return out, signer, nil
}

// VerifyDetached ...
func VerifyDetached(sig []byte, b []byte) (keys.ID, error) {
	s := &saltpack{}
	var spk ksaltpack.SigningPublicKey
	var err error
	enc, armored := detectSignDetached(sig)
	switch enc {
	case SignEncoding:
		if armored {
			spk, _, err = ksaltpack.Dearmor62VerifyDetached(signVersionValidator, b, string(sig), s)
		} else {
			spk, err = ksaltpack.VerifyDetached(signVersionValidator, b, sig, s)
		}
	default:
		return "", errors.Errorf("invalid data")
	}
	if err != nil {
		return "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return "", errors.Wrapf(err, "failed to verify")
	}
	return signer, nil
}

// NewSignStream ...
func NewSignStream(w io.Writer, armored bool, detached bool, key *keys.EdX25519Key) (io.WriteCloser, error) {
	if armored && detached {
		return ksaltpack.NewSignDetachedArmor62Stream(ksaltpack.Version1(), w, newSignKey(key), "")
	}
	if armored {
		return ksaltpack.NewSignArmor62Stream(ksaltpack.Version1(), w, newSignKey(key), "")
	}
	if detached {
		return ksaltpack.NewSignDetachedStream(ksaltpack.Version1(), w, newSignKey(key))
	}
	return ksaltpack.NewSignStream(ksaltpack.Version1(), w, newSignKey(key))
}

// NewVerifyStream ...
func NewVerifyStream(r io.Reader) (io.Reader, keys.ID, error) {
	s := &saltpack{}
	buf := bufio.NewReader(r)
	peek, err := buf.Peek(512)
	if err != nil {
		if err != io.EOF {
			return nil, "", err
		}
	}
	var spk ksaltpack.SigningPublicKey
	var reader io.Reader
	enc, armored := detectSign(peek)
	switch enc {
	case SignEncoding:
		if armored {
			spk, reader, _, err = ksaltpack.NewDearmor62VerifyStream(signVersionValidator, buf, s)
		} else {
			spk, reader, err = ksaltpack.NewVerifyStream(signVersionValidator, buf, s)
		}
	default:
		err = errors.Errorf("invalid data")
	}
	if err != nil {
		return nil, "", convertSignKeyErr(err)
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to verify")
	}
	return reader, signer, nil
}

// VerifyDetachedReader ...
func VerifyDetachedReader(sig []byte, r io.Reader) (keys.ID, error) {
	s := &saltpack{}
	var spk ksaltpack.SigningPublicKey
	var err error
	enc, armored := detectSignDetached(sig)
	switch enc {
	case SignEncoding:
		if armored {
			spk, _, err = ksaltpack.Dearmor62VerifyDetachedReader(signVersionValidator, r, string(sig), s)
		} else {
			spk, err = ksaltpack.VerifyDetachedReader(signVersionValidator, r, sig, s)
		}
	default:
		return "", errors.Errorf("invalid data")
	}
	signer, err := edX25519KeyID(spk.ToKID())
	if err != nil {
		return "", errors.Wrapf(err, "failed to verify")
	}
	return signer, nil
}

// StripBefore removes text before BEGIN.
func StripBefore(message string) string {
	n := strings.Index(message, "BEGIN")
	if n == 0 {
		return message
	}
	return message[n:]
}

// SignFile signs a file.
func SignFile(in string, out string, key *keys.EdX25519Key, armored bool, detached bool) error {
	logger.Infof("Signing %s to %s", in, out)

	if in == "" {
		return errors.Errorf("in not specified")
	}
	if out == "" {
		return errors.Errorf("out not specified")
	}

	outTmp := out + ".tmp"
	outFile, err := os.Create(outTmp)
	if err != nil {
		return err
	}
	defer func() {
		_ = outFile.Close()
		_ = os.Remove(outTmp)
	}()
	writer := bufio.NewWriter(outFile)

	logger.Debugf("Sign armored=%t detached=%t", armored, detached)
	stream, err := NewSignStream(writer, armored, detached, key)
	if err != nil {
		return err
	}

	inFile, err := os.Open(in) // #nosec
	if err != nil {
		return err
	}
	defer func() {
		_ = inFile.Close()
	}()
	reader := bufio.NewReader(inFile)
	if _, err := reader.WriteTo(stream); err != nil {
		return err
	}

	if err := stream.Close(); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := inFile.Close(); err != nil {
		return err
	}
	if err := outFile.Close(); err != nil {
		return err
	}

	if err := os.Rename(outTmp, out); err != nil {
		return err
	}

	return nil
}

// VerifyFile outputs verified file from in path.
func VerifyFile(in string, out string) (keys.ID, error) {
	logger.Infof("Verify %s to %s", in, out)
	if in == "" {
		return "", errors.Errorf("in not specified")
	}
	if out == "" {
		return "", errors.Errorf("out not specified")
	}

	inFile, err := os.Open(in) // #nosec
	if err != nil {
		return "", err
	}
	defer func() {
		_ = inFile.Close()
	}()
	reader := bufio.NewReader(inFile)

	verifyReader, kid, err := NewVerifyStream(reader)
	if err != nil {
		return "", errors.Wrapf(err, "failed to verify file")
	}

	outTmp := out + ".tmp"
	outFile, err := os.Create(outTmp)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = outFile.Close()
		_ = os.Remove(outTmp)
	}()

	writer := bufio.NewWriter(outFile)

	if _, err := writer.ReadFrom(verifyReader); err != nil {
		return "", err
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	if err := inFile.Close(); err != nil {
		return "", err
	}
	if err := outFile.Close(); err != nil {
		return "", err
	}

	if err := os.Rename(outTmp, out); err != nil {
		return "", err
	}

	return kid, nil
}

// VerifyFileDetached verifies file at path with signature.
func VerifyFileDetached(sig []byte, path string) (keys.ID, error) {
	file, err := os.Open(path) // #nosec
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	reader := bufio.NewReader(file)
	return VerifyDetachedReader(sig, reader)
}
