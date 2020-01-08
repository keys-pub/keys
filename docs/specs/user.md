# User

A user is an account on another service (like Github or Twitter) linked to a key with a signed
[Statement](specs/sigchain.md#Statement).

This allows others to search and verify a key as belonging to a user/account on a 3rd party service.

The steps are:

1. Generate a user signed statement (saltpack armored) with the name, service and key identifier.
2. Place the statement on the service at an URL controlled by the account.
3. Save a signed statement in the sigchain including all the information about including the URL on the service where to find the signed statement.

## Fields

The signed statement signs the following fields:

| Fields | Description                     |
| ------ | ------------------------------- |
| `k`    | Key identifier.                 |
| `n`    | Username.                       |
| `sr`   | Service name (github, twitter). |

For example,

```json
{
  "k": "kpe132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw",
  "n": "gabriel",
  "sr": "github"
}
```

You can create a signed user statement from the command line:

```shell
keys user sign -kid "kpe132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw" \
-service "github" -name "gabriel"
```

```txt
BEGIN MESSAGE.
NWfTZwmVoF2JyaG 19zFMzvQTGCtapx tjd0qyJZPEAMETg wsopnv9Whmc2CHY
LHduC9i3guXLTdY HzpluDb1KleTCKq 6Xr2LSniILjRxYM WwtzXWH1P9g2DiQ
VkxL51PZaN6xp1K tnb72l9Ym5Y0sGC NDsulKa7ILrP1ov zLavKEWDbxeyl6V
J5HlOPb8qaFXC7T oGM2twKIEmX6Ekk ynCw60oQokntgcx XGM1.
END MESSAGE.
```

Place this user signed statement at a location or the service, for example, [https://gist.github.com/gabriel/02fae653e737bdeb7c730da669c949b1/edit](https://gist.github.com/gabriel/02fae653e737bdeb7c730da669c949b1/edit).

## Sigchain Statement

After placing the signed statement at an URL, saved a signed statement in the sigchain with the additional information.

| Fields | Description                     |
| ------ | ------------------------------- |
| `k`    | Key identifier.                 |
| `n`    | Username.                       |
| `sq`   | Sigchain seq (position).        |
| `sr`   | Service name (github, twitter). |
| `u`    | URL to signed statement.        |

For example,

```json
{
  "k": "kpe132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw",
  "n": "gabriel",
  "sq": 2,
  "sr": "github",
  "u": "https://gist.github.com/gabriel/02fae653e737bdeb7c730da669c949b1"
}
```

You can save to the a user statement to the sigchain from the command line:

```shell
keys user add -kid "kpe132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw" \
-service "github" -name "gabriel" \
-url "https://gist.github.com/gabriel/02fae653e737bdeb7c730da669c949b1"
```

Using the kid and seq (sigchain position), you can lookup the sigchain item to find the user signed statement:

```shell
curl https://keys.pub/sigchain/ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw/1
```

```json
{
  ".sig": "PiSMFgz2SiH+2hcb60uza6GLWHtmx6bK+hNVF8uFvSbkweFCAdPUc8WUbSfVo3fL7Msbf69kqwjjj2Rv98CxAA==",
  "data": "eyJraWQiOiJRQnJiekNXSzVNZjVmenpGYXlDcVY0Zm5aYUdVVE1SanZBeHlFcWYzODhzdCIsIm5hbWUiOiJnYWJyaWVsIiwic2VxIjoyLCJzZXJ2aWNlIjoiZ2l0aHViIiwidXJsIjoiaHR0cHM6Ly9naXN0LmdpdGh1Yi5jb20vZ2FicmllbC8wMWNlNDNhYTg2N2FhM2IwMTA1YTZkMThiZTdjOThmNiJ9",
  "kid": "kpe132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw",
  "prev": "w8O6TeLPbNPfYGJhv6xiEE4952hwNMYOoDP4bP3EWOQ=",
  "seq": 2,
  "type": "user"
}
```

Or use the command line:

```shell
keys sigchain show -kid ed132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqrkl9gw -seq 2
```

## Revoke

You can remove the user account by revoking the sigchain statement or removing the signed statement at the URL.
