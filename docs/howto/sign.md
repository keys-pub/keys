# Signing

## `keys sign`

Sign from stdin to stdout (armored).

```shell
echo -n "I'm alice 🤓" | keys sign -armor -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st > msg.sig
```

Sign image.png to image.png.sig.

```shell
keys sign -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st -in image.png -out image.png.sig
```

Sign image.png to image.png.sig (from stdin to stdout).

```shell
cat image.png | keys sign -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st > image.png.sig
```

## `keys verify`

Verify from stdin.

```shell
cat msg.sig | keys verify -armor -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st
I'm alice 🤓
```

Verify from file to stdout.

```shell
keys verify -armor -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st -in msg.sig
I'm alice 🤓
```

Verify image.png.sig to image.png.

```shell
keys verify -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st -in image.png.sig -out image.png
```
