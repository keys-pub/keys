# Sigchain

The sigchain is an ordered sequence of [Statement](https://godoc.org/github.com/keys-pub/keys#Statement)'s signed by a key.

This spec is similar to [Keybase Sigchain](https://keybase.io/docs/teams/sigchain_v2) or the [Secure Scuttlebutt Feed](https://ssbc.github.io/scuttlebutt-protocol-guide/#structure).

## Statement

A [Statement](https://godoc.org/github.com/keys-pub/keys#Statement) describes signed data for use in a
sigchain.

### Format

This is compatible as a JSON canonical format (ordered keys, no whitespace, with only string and integer values).

| Field  | Type   | Description                                                                                       |
| ------ | ------ | ------------------------------------------------------------------------------------------------- |
| .sig   | string | Signature (base64 encoded).                                                                       |
| data   | string | Data (base64 encoded).                                                                            |
| kid    | string | Key id used to sign.                                                                              |
| prev   | string | Hash (SHA-256, base64 encoded) of previous sigchain statement, or omitted for the root statement. |
| seq    | int    | Sequence number, starting at 1 for the root statement.                                            |
| revoke | int    | (Optional) Sequence number of a statement to revoke.                                              |
| ts     | int    | (Optional) Timestamp, number of milliseconds since 1 January 1970 00:00 UTC.                      |
| type   | string | (Optional) Statement type ("", "revoke", "user", "bpk").                                          |

The format for a statement:

```text
{".sig":"<base64 signature>","kid":"<kid>","data":"<base64 data>","prev":"<base64 prev hash>","seq":<integer>,"ts":<integer>}
```

The format for a revoke statement:

```text
{".sig":"<base64 signature>","kid":"<kid>","prev":"<base64 prev hash>","prev":"<base64 prev hash>","revoke":<integer>,"seq":<integer>,"ts":<integer>,"type":"revoke"}
```

### Signature

The signature (`.sig`) is the signature bytes (base64 encoded) of the specific serialization, for example:

### Specific Serialization

The specific serialization (or the bytes to sign) is the statement without the ".sig" value":

```text
{".sig":"","data":"<base64 data>","kid":"<kid>","prev":"<base64 prev hash>","seq":<integer>,"ts":<integer>,"type":"<type>"}
```

### Verifying the Signature

It is important to verify the bytes match the specific serialization.
You can do this by stripping out the .sig value, which is the characters in the range [9:97], and verifying the signature on those bytes.

See [How (not) to sign a JSON object](https://latacora.micro.blog/2019/07/24/how-not-to.html).

### REST API

You can access sigchains via the [REST API](rest-api/sigchains.md).

## Usage

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/keys-pub/keys"
)

func main() {
    alice := keys.GenerateEd25519Key()
    sc := keys.NewSigchain(alice.PublicKey())

    // Create root statement
    st, err := keys.GenerateStatement(sc, []byte("hi! 🤓"), alice, "", time.Now())
    if err != nil {
        log.Fatal(err)
    }
    if err := sc.Add(st); err != nil {
        log.Fatal(err)
    }

    // Add 2nd statement
    st2, err := keys.GenerateStatement(sc, []byte("2nd message"), alice, "", time.Now())
    if err != nil {
        log.Fatal(err)
    }
    if err := sc.Add(st2); err != nil {
        log.Fatal(err)
    }

    // Revoke 2nd statement
    if _, err := sc.Revoke(2, alice); err != nil {
        log.Fatal(err)
    }

    // Spew
    spew, err := sc.Spew()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(spew.String())
}
```

[Playground](https://play.golang.org/p/ZTN5Rs-RkN9)

```text
/sigchain/Xd3LgxvnBjrwaL3Tq3BfjzPtob2txwc5ysqTxFSJXEGe/1 {".sig":"4cfMtMXXvNJnPysui3LRsFStJci4lR7o/4gyOskW7vXCy/e4IfwVlp5GfvRbU9M41IstHNsAjnpyIL63LmfPCA==","data":"aGkhIPCfpJM=","kid":"Xd3LgxvnBjrwaL3Tq3BfjzPtob2txwc5ysqTxFSJXEGe","seq":1}
/sigchain/Xd3LgxvnBjrwaL3Tq3BfjzPtob2txwc5ysqTxFSJXEGe/2 {".sig":"4yA5kNxB+qKDKzkzyhZ4sZDg0Jcr1CB2QOtGye51QP7QsLrRRV0LEWlqSTE98QweFiL9V6GWrJ77s0C7Lg8cCA==","data":"Mm5kIG1lc3NhZ2U=","kid":"Xd3LgxvnBjrwaL3Tq3BfjzPtob2txwc5ysqTxFSJXEGe","prev":"zFVzWYcbn8OprxOwqA8gyZ5iPJh0yKgnMWsZe5Ll+yM=","seq":2}
/sigchain/Xd3LgxvnBjrwaL3Tq3BfjzPtob2txwc5ysqTxFSJXEGe/3 {".sig":"Vri6rGGbd6gNS3rr5HE3w5W1SzXvLBNjy2B+vTco83tAUY1zeWpYUno2wuAQuBjsw1I/gEYia3NlN9/I/SN7CQ==","kid":"Xd3LgxvnBjrwaL3Tq3BfjzPtob2txwc5ysqTxFSJXEGe","prev":"XxzcqXBx4WTk7L16AT167Jay4C5+HVTUpMHcJkaOC/s=","revoke":2,"seq":3,"type":"revoke"}
```
