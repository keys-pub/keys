// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// From:
// https://github.com/FiloSottile/age/blob/master/internal/age/ssh.go

package keys

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ScaleFT/sshkeys"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// ParseSSHPublicKey parses a SSH public key.
func ParseSSHPublicKey(s string) (Key, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("malformed SSH recipient: %q: %v", s, err)
	}

	switch t := pk.Type(); t {
	case "ssh-rsa":
		return nil, errors.Errorf("SSH RSA key not currently supported")
	case "ssh-ed25519":
		if pk, ok := pk.(ssh.CryptoPublicKey); ok {
			if pk, ok := pk.CryptoPublicKey().(ed25519.PublicKey); ok {
				if len(pk) != 32 {
					return nil, errors.Errorf("invalid length for ssh ed25519 public key")
				}
				return NewEdX25519PublicKey(Bytes32(pk)), nil
			}
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown SSH recipient type: %q", t)
	}
}

func trimLineSpace(b []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(b))
	out := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return []byte{}, err
	}
	return []byte(strings.Join(out, "\n")), nil
}

// ParseSSHKey parses a SSH private key.
func ParseSSHKey(pemBytes []byte, passphrase []byte, trim bool) (Key, error) {
	if trim {
		b, err := trimLineSpace(pemBytes)
		if err != nil {
			return nil, err
		}
		pemBytes = b
	}

	var k interface{}
	if len(passphrase) > 0 {
		var err error
		k, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse ssh key with passphrase")
		}
	} else {
		var err error
		k, err = ssh.ParseRawPrivateKey(pemBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse ssh key")
		}
	}

	switch k := k.(type) {
	case *ed25519.PrivateKey:
		if len(*k) != 64 {
			return nil, errors.Errorf("invalid ed25519 private key length")
		}
		return NewEdX25519KeyFromPrivateKey(Bytes64(*k)), nil
	case ed25519.PrivateKey:
		if len(k) != 64 {
			return nil, errors.Errorf("invalid ed25519 private key length")
		}
		return NewEdX25519KeyFromPrivateKey(Bytes64(k)), nil
	case *rsa.PrivateKey:
		return nil, errors.Errorf("SSH RSA key not currently supported")
	}

	return nil, fmt.Errorf("unsupported SSH identity type: %T", k)
}

// EncodeToSSH encodes a EdX25519Key for SSH.
func (k *EdX25519Key) EncodeToSSH(password []byte) ([]byte, error) {
	key := ed25519.PrivateKey(k.Private())
	return sshkeys.Marshal(key, &sshkeys.MarshalOptions{
		Passphrase: password,
	})
}

// EncodeToSSHAuthorized encodes a EdX25519PublicKey for SSH.
func (k *EdX25519PublicKey) EncodeToSSHAuthorized() []byte {
	b := &bytes.Buffer{}
	b.WriteString(ssh.KeyAlgoED25519)
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)

	w := struct {
		Name     string
		KeyBytes []byte
	}{
		ssh.KeyAlgoED25519,
		k.Bytes(),
	}
	mb := ssh.Marshal(&w)

	if _, err := e.Write(mb); err != nil {
		panic(err)
	}
	if err := e.Close(); err != nil {
		panic(err)
	}
	// b.WriteByte('\n')
	return b.Bytes()
}

// SSHSigner interface.
func (k *EdX25519Key) SSHSigner() ssh.Signer {
	signer, err := ssh.NewSignerFromKey(k.Signer())
	if err != nil {
		panic(err)
	}
	return signer
}
