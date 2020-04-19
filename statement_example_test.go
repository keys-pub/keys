package keys_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/keys-pub/keys"
)

func ExampleNewSignedStatement() {
	clock := newClock()

	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	st := keys.NewSignedStatement(bytes.Repeat([]byte{0x01}, 16), sk, "", clock.Now())

	data := st.SpecificSerialization()
	fmt.Printf("%s\n", string(data))

	b, err := st.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(b))

	// Output:
	// {".sig":"","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","ts":1234567890001}
	// {".sig":"XcDbICx+rKfYUPgwqU08lLChmjJL5Eco/LxLHNA2C0oZILITnVng04XzFK4wCj2qObkAEyzYywKUb/zn3VACDA==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","ts":1234567890001}
}
