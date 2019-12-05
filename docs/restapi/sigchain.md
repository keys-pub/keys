# REST API (Sigchain)

The _api.keys.app_ server provides an API for publishing and accessing sigchains (see [Sigchain](../sigchain.md)).

## GET /sigchain/:kid

Get a sigchain for a user public key.

```shell
curl https://api.keys.app/sigchain/GCyz8QoBP3tw3YzHMguLxoJJ8gKdYoLJbBE2PWkphGMm
```

```json
{
  "kid": "GCyz8QoBP3tw3YzHMguLxoJJ8gKdYoLJbBE2PWkphGMm",
  "statements": [
    {
      ".sig": "7GgCcvfme86kxOhILl6BFz4qWCR0x5S1tyDfqj6SioNhMfr136ZOwWOZ4zOwXu4UGJWR115bbyyEonS6vtWCBA==",
      "data": "GYxjX/qVppWLMhSJZiddvejpe+9yeAZ7RguM2l6/fB8=",
      "kid": "GCyz8QoBP3tw3YzHMguLxoJJ8gKdYoLJbBE2PWkphGMm",
      "seq": 1,
      "type": "bpk"
    },
    {
      ".sig": "PLcfqS8S6qwy/fCuuasLGQoH1QSsPG9PnlSqul4Renw3uanUG7F7E2EI1d7X9VL6N8tZc0Y87iHxyuklDPR0BQ==",
      "data": "eyJraWQiOiJHQ3l6OFFvQlAzdHczWXpITWd1THhvSko4Z0tkWW9MSmJCRTJQV2twaEdNbSIsIm5hbWUiOiJnYWJyaWVsIiwic2VxIjoyLCJzZXJ2aWNlIjoiZ2l0aHViIiwidXJsIjoiaHR0cHM6Ly9naXN0LmdpdGh1Yi5jb20vZ2FicmllbC9kMTJmNWNhMDVmNWQwZmM5ODk5ZjRhM2MyMjc2MTE4ZSJ9",
      "kid": "GCyz8QoBP3tw3YzHMguLxoJJ8gKdYoLJbBE2PWkphGMm",
      "prev": "MhyJn8CvkjWs8Dbzrp5JrcG5bPf4JriAxQEPuWlCA70=",
      "seq": 2,
      "type": "user"
    }
  ]
}
```

| Response   | Description                                              |
| ---------- | -------------------------------------------------------- |
| id         | ID                                                       |
| statements | Array&lt;[Statement](../specs/sigchain.md#Statement)&gt; |

### Statement

| Field  | Type   | Description                                                                                        |
| ------ | ------ | -------------------------------------------------------------------------------------------------- |
| data   | string | Data (base64 encoded).                                                                             |
| kid    | id     | User public key id used to sign.                                                                   |
| prev   | string | Hash (SHA-256, base64 encoded) of previous sigchain statement, or ommitted for the root statement. |
| seq    | int    | Sequence number, starting at 1 for the root statement.                                             |
| sig    | string | Signature (base64 encoded) of this statement.                                                      |
| revoke | int    | (Optional) Sequence number of a statement to revoke (or 0).                                        |
| type   | string | (Optional) Statement type ("revoke", "user").                                                      |

## PUT /sigchain/:kid/:seq

The body content should be a sigchain [Statement](../sigchain.md#Statement).

```shell
curl -X PUT -d '{".sig":"cBkbRkMERy0yo436kRuWNF/O4E2OcVnbw9uy2o/D1Gc9+hXpIHkasnusqkknUyV+l9QMKVRbbLe121Ws5jeSBQ==","data":"4xsu+g26GIHBobmLN+kKEFOuYIBA3eY1FrGLDI9WEFc=","kid":"QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st","seq":1,"type":"bpk"}' \
https://api.keys.app/sigchain/QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st/1
```

It must be a valid signed sigchain statement by the sign key. If it exists already, returns 409 error.
The max size for the msg is 16KB.

## GET /sigchains

List all sigchain statements for everyone.
The results are in order of the statements added, and is meant for sync'ing all sigchains to the local db.

| Params  | type           | Description                                                      |
| ------- | -------------- | ---------------------------------------------------------------- |
| version | string         | Returns sigchain statements added since this version.            |
| limit   | int [1-10000]  | Limit number of results. Defaults to 1000. Max allowed is 10000. |
| include | strings ["md"] | Additional fields to include, "md" (metadata).                   |

```shell
curl https://api.keys.app/sigchains?limit=2
```

```json
{
  "statements": [
    {
      ".sig": "7gEWAKsRoJfZGjH9GcTeobYoNAIMU2hcxn0AK8H7NzgmDodeW/HcBStHf6zfdEmIRRj0UlEuP0Ia5zvUb00tAA==",
      "data": "bAx98tGoViK37AmuVBuS6atWOPQ6AdTRxW8qSww+a2g=",
      "kid": "FXotuKi9YCkxbzQ1VSPgjU8uAeA8C9y1nHdTKjdkuuj8",
      "seq": 1,
      "type": "bpk"
    },
    {
      ".sig": "tmrFQi4ORD6Nh9945g+gQ644DWOaeqQVfqC8p4/F5orb3SA9NlY/otOUI6ijsCWorYhiNdCKOxEvk6oETNc4Aw==",
      "data": "62YHurhoNpdLx56K+0hnpWt/hBQSvQFcFGtiNnobHm0=",
      "kid": "K6FZKkFWEdZvt2ogP5XXL2kPuiBSwfXLrGi55DvFbZxr",
      "seq": 1,
      "type": "bpk"
    }
  ],
  "version": "1569350373586"
}
```

| Response   | Description                     |
| ---------- | ------------------------------- |
| statements | Statements.                     |
| version    | Current version.                |
| md         | Metadata (if asked to include). |
