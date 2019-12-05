package saltpack

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

const aliceID = keys.ID("ZoxBoAcN3zUr5A11Uyq1J6pscwKFo2oZSFbwfT7DztXg")
const bobID = keys.ID("6d35v6U3GfePrTjFwtak5yTUpkEyWA7tQQ2gDzZdX89x")

const aliceSeed = "stairs portion summer trade mask nut ostrich hope subway gap daughter sword empty jungle comfort fiscal liberty stadium hint lonely tired found elegant clump"
const bobSeed = "patient property kitten adapt lunar symptom flag system gun mandate high ice increase disorder party maze earth profit reward lift wool smile test economy"

type clock struct {
	t time.Time
}

func newClock() *clock {
	t := keys.TimeFromMillis(1234567890000)
	return &clock{
		t: t,
	}
}

func (c *clock) Now() time.Time {
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

func testEncrypt(t *testing.T, mode Mode) {
	clock := newClock()
	ksa := keys.NewMemKeystore()
	alice, err := keys.NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	err = ksa.SaveKey(alice, false, clock.Now())
	require.NoError(t, err)
	spa := NewSaltpack(ksa)
	spa.SetMode(mode)

	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	spb.SetMode(mode)
	bob, err := keys.NewKeyFromSeedPhrase(bobSeed, false)
	require.NoError(t, err)
	err = ksb.SaveKey(bob, false, clock.Now())
	require.NoError(t, err)

	message := []byte("hi bob")

	encrypted, err := spa.Seal(message, alice, bob.PublicKey())
	require.NoError(t, err)

	out, sender, err := spb.Open(encrypted)
	require.NoError(t, err)
	require.Equal(t, message, out)
	require.Equal(t, alice.ID(), sender)

	_, err = spa.Seal(message, alice, nil)
	require.EqualError(t, err, "nil recipient")
}

func testEncryptStream(t *testing.T, mode Mode) {
	clock := newClock()
	ksa := keys.NewMemKeystore()
	alice, err := keys.NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	err = ksa.SaveKey(alice, false, clock.Now())
	require.NoError(t, err)
	spa := NewSaltpack(ksa)
	spa.SetMode(mode)

	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	spb.SetMode(mode)
	bob, err := keys.NewKeyFromSeedPhrase(bobSeed, false)
	require.NoError(t, err)
	err = ksb.SaveKey(bob, false, clock.Now())
	require.NoError(t, err)

	message := []byte("hi bob")

	var buf bytes.Buffer
	encrypted, err := spa.NewSealStream(&buf, alice, bob.PublicKey())
	require.NoError(t, err)
	n, err := encrypted.Write(message)
	require.NoError(t, err)
	require.Equal(t, len(message), n)
	encrypted.Close()

	stream, sender, err := spb.NewOpenStream(&buf)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), sender)
	out, err := ioutil.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, message, out)
}

func testOpenError(t *testing.T, mode Mode) {
	clock := newClock()
	ksa := keys.NewMemKeystore()
	alice, err := keys.NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	err = ksa.SaveKey(alice, false, clock.Now())
	require.NoError(t, err)
	spa := NewSaltpack(ksa)
	spa.SetMode(mode)

	ksb := keys.NewMemKeystore()
	spb := NewSaltpack(ksb)
	spb.SetMode(mode)

	encrypted, err := spa.Seal([]byte("alice's message"), alice, alice.PublicKey())
	require.NoError(t, err)

	_, _, err = spb.Open(encrypted)
	require.EqualError(t, err, "no decryption key found for message")
}

func ExampleNewSaltpack() {
	alice := keys.GenerateKey()
	bob := keys.GenerateKey()

	// Sigchain store
	scs := keys.NewSigchainStore(keys.NewMem())

	// Alice's keystore, save alice's key
	ksa := keys.NewKeystore()
	ksa.SetKeyring(keyring.NewMem())
	ksa.SetSigchainStore(scs)
	if err := ksa.SaveKey(alice, true, time.Now()); err != nil {
		log.Fatal(err)
	}
	spa := NewSaltpack(ksa)
	msg := []byte("Hey bob, it's alice. The passcode is 12345.")
	// Alice encrypts
	encrypted, err := spa.Seal(msg, alice, bob.PublicKey())
	if err != nil {
		log.Fatal(err)
	}

	// Bob's keystore, save bob's key and alice's public key
	ksb := keys.NewKeystore()
	ksb.SetKeyring(keyring.NewMem())
	ksb.SetSigchainStore(scs)
	spb := NewSaltpack(ksb)
	if err := ksb.SaveKey(bob, true, time.Now()); err != nil {
		log.Fatal(err)
	}
	// Bob decrypts
	out, sender, err := spb.Open(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	if sender != alice.ID() {
		log.Fatalf("Sender not alice")
	}
	fmt.Printf("%s\n", string(out))
	// Output:
	// Hey bob, it's alice. The passcode is 12345.
}

func ExampleNewCryptoStore() {
	alice := keys.GenerateKey()
	bob := keys.GenerateKey()

	db := keys.NewMem()
	scs := keys.NewSigchainStore(db)

	// Alice's Keystore
	ksa := keys.NewMemKeystore()
	ksa.SetSigchainStore(scs)
	if err := ksa.SaveKey(alice, true, time.Now()); err != nil {
		log.Fatal(err)
	}
	cpa := NewSaltpack(ksa)
	kdsa := keys.NewCryptoStore(db, cpa)

	if _, err := kdsa.Seal(context.TODO(), "test/key1", []byte("secret"), alice, bob.PublicKey()); err != nil {
		log.Fatal(err)
	}

	// Bob's Keystore
	ksb := keys.NewMemKeystore()
	ksb.SetSigchainStore(scs)
	if err := ksb.SaveKey(bob, true, time.Now()); err != nil {
		log.Fatal(err)
	}
	cpb := NewSaltpack(ksb)
	kdsb := keys.NewCryptoStore(db, cpb)
	opened, err := kdsb.Open(context.TODO(), "test/key1")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", opened.Data)
	// Output:
	// secret
}
