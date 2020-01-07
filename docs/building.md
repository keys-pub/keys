# Building from Source

There are 2 binaries, the service `keysd` and the client `keys`.

```shell
GO111MODULE=on go install github.com/keys-pub/keysd
GO111MODULE=on go install github.com/keys-pub/keysd/service/keys
```

On macOS, you should codesign the binaries:

```shell
> codesign --verbose --sign "Developer ID Application: ????" ~/go/bin/keysd
> codesign --verbose --sign "Developer ID Application: ????" ~/go/bin/keys
```
