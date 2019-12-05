# Building from Source

There are 2 binaries, the service `keysd` and the client `keys`.

```shell
GO111MODULE=on go install github.com/keys-pub/keysd
GO111MODULE=on go install github.com/keys-pub/keysd/service/keys
```

On macOS, you need to codesign the binaries:

```shell
> codesign --verbose --sign "Developer ID Application: ????" ~/go/bin/keysd
> codesign --verbose --sign "Developer ID Application: ????" ~/go/bin/keys
```

Codesigning is important since the system keychain relies on signed binaries to
secure access.
