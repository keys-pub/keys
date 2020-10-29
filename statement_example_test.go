package keys_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/keys-pub/keys"
)

func ExampleStatement() {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	st := &keys.Statement{
		KID:  sk.ID(),
		Data: bytes.Repeat([]byte{0x01}, 16),
		Type: "test",
	}
	if err := st.Sign(sk); err != nil {
		log.Fatal(err)
	}

	data := st.SpecificSerialization()
	fmt.Printf("%s\n", string(data))

	b, err := st.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(b))

	b, err = json.Marshal(st)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(b))

	// Output:
	// {".sig":"","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","type":"test"}
	// {".sig":"CFD9cK9gIB3sAEqpDwmZM0JFFO4/+RpX9uoAD25G3F1o8Af+pTk6pI4GPqAZ5FhEw1rUDfL02Qnohtx05LQxAg==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","type":"test"}
	// {".sig":"CFD9cK9gIB3sAEqpDwmZM0JFFO4/+RpX9uoAD25G3F1o8Af+pTk6pI4GPqAZ5FhEw1rUDfL02Qnohtx05LQxAg==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","type":"test"}
}
