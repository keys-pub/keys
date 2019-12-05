# User

A user is an account on another service (like Github or Twitter) linked to a [Key](specs/key.md) with a signed
[Statement](specs/sigchain.md#Statement).

This allows others to search and verify your key as belonging to a user/account on a 3rd party service.

The steps are:

1. Generate a user signed statement (saltpack armored) with the name, service and key identifier (kid).
2. Place the statement on the service at an URL controlled by the account.
3. Save a signed statement in the sigchain including all the information about including the URL on the service where to find the signed statement.

## User Statement

The user signed statement describes the name, service and kid.

| Fields    | Description                     |
| --------- | ------------------------------- |
| `kid`     | Key identifier.                 |
| `name`    | Username.                       |
| `service` | Service name (github, twitter). |

For example,

```json
{
  "kid": "QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st",
  "name": "gabriel",
  "service": "github"
}
```

You can create a signed user statement from the command line:

```shell
keys user sign -kid "QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st" \
-service "github" -name "gabriel"
```

```txt
BEGIN MESSAGE.
6C7cjOwfS25pYjf ykSIvIk1cHf5d3G ffL09Puva7QKTYq AOIVZnd7N1B23T3
biMftdYkd4LwOXP hGQkwcONSKtTCKs gwSpYAiSWCPT9aL xOi6m8aukRziLhy
6zRw0eOntOIeF4I JQZvA7PVC2cJdan K9eCUmoVaUKLqsb v91bARw0FcF62QB
QA5HdBgu10Qrl.
END MESSAGE.
```

Place this user signed statement at a location or the service, for example, [https://gist.github.com/gabriel/01ce43aa867aa3b0105a6d18be7c98f6](https://gist.github.com/gabriel/01ce43aa867aa3b0105a6d18be7c98f6).

## Sigchain Statement

After placing the signed statement at an URL, saved a signed statement in the sigchain with the additional information.

| Fields    | Description                     |
| --------- | ------------------------------- |
| `kid`     | Key identifier.                 |
| `name`    | Username.                       |
| `seq`     | Sigchain seq (position).        |
| `service` | Service name (github, twitter). |
| `url`     | URL to signed statement.        |

For example,

```json
{
  "kid": "QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st",
  "name": "gabriel",
  "seq": 2,
  "service": "github",
  "url": "https://gist.github.com/gabriel/01ce43aa867aa3b0105a6d18be7c98f6"
}
```

You can save to the a user statement to the sigchain from the command line:

```shell
keys user add -kid "QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st" \
-service "github" -name "gabriel" \
-url "https://gist.github.com/gabriel/01ce43aa867aa3b0105a6d18be7c98f6"
```

Using the kid and seq (sigchain position), you can lookup the sigchain item to find the user signed statement:

```shell
curl https://keys.pub/sigchain/QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st/2
```

```json
{
  ".sig": "PiSMFgz2SiH+2hcb60uza6GLWHtmx6bK+hNVF8uFvSbkweFCAdPUc8WUbSfVo3fL7Msbf69kqwjjj2Rv98CxAA==",
  "data": "eyJraWQiOiJRQnJiekNXSzVNZjVmenpGYXlDcVY0Zm5aYUdVVE1SanZBeHlFcWYzODhzdCIsIm5hbWUiOiJnYWJyaWVsIiwic2VxIjoyLCJzZXJ2aWNlIjoiZ2l0aHViIiwidXJsIjoiaHR0cHM6Ly9naXN0LmdpdGh1Yi5jb20vZ2FicmllbC8wMWNlNDNhYTg2N2FhM2IwMTA1YTZkMThiZTdjOThmNiJ9",
  "kid": "QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st",
  "prev": "w8O6TeLPbNPfYGJhv6xiEE4952hwNMYOoDP4bP3EWOQ=",
  "seq": 2,
  "type": "user"
}
```

Or use the command line:

```shell
keys sigchain show -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st -seq 2
```

## Revoke

You can remove the user account by revoking the sigchain statement or removing the signed statement at the URL.
