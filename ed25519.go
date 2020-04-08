// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package keys

import (
	"crypto/sha512"
	"math/big"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

var x25519P, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) []byte {
	// ed25519.PublicKey is a little endian representation of the y-coordinate,
	// with the most significant bit set based on the sign of the x-coordinate.
	bigEndianY := make([]byte, ed25519.PublicKeySize)
	for i, b := range pk {
		bigEndianY[ed25519.PublicKeySize-i-1] = b
	}
	bigEndianY[0] &= 0b0111_1111

	// The Montgomery u-coordinate is derived through the bilinear map
	//
	//     u = (1 + y) / (1 - y)
	//
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption.
	y := new(big.Int).SetBytes(bigEndianY)
	denom := big.NewInt(1)
	denom.ModInverse(denom.Sub(denom, y), x25519P) // 1 / (1 - y)
	u := y.Mul(y.Add(y, big.NewInt(1)), denom)
	u.Mod(u, x25519P)

	out := make([]byte, curve25519.PointSize)
	uBytes := u.Bytes()
	for i, b := range uBytes {
		out[len(uBytes)-i-1] = b
	}

	return out
}

func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	if _, err := h.Write(pk.Seed()); err != nil {
		panic(err)
	}
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}
