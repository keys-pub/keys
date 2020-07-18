package keys_test

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/keys-pub/keys"
)

func ExampleNewSignedStatement() {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	st := keys.NewSignedStatement(bytes.Repeat([]byte{0x01}, 16), sk, "", time.Time{})

	data := st.SpecificSerialization()
	fmt.Printf("%s\n", string(data))

	b, err := st.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(b))

	// Output:
	// {".sig":"","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"}
	// {".sig":"lXVLUr1eRfI0c5an0h9VBN717o46TAcsC04L0oYvr8h3XUASYskGywo5PaT2V61nQvPE1PYx7OsV4jOocc4pAA==","data":"AQEBAQEBAQEBAQEBAQEBAQ==","kid":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"}
}
