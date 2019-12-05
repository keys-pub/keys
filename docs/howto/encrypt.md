# Encryption

## `keys encrypt`

Encrypt text to armored msg.enc (from stdin).

```shell
echo -n "My secret 🤓" |  keys encrypt -armor -sender QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st \
-recipients FXotuKi9YCkxbzQ1VSPgjU8uAeA8C9y1nHdTKjdkuuj8,QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st > msg.enc
```

Encrypt image.png to image.png.enc (using -in and -out).

```shell
keys encrypt -sender QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st \
-recipients FXotuKi9YCkxbzQ1VSPgjU8uAeA8C9y1nHdTKjdkuuj8,QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st \
-in image.png -out image.png.enc
```

Encrypt image.png to image.png.enc (using stdin and stdout).

```shell
cat image.png | keys encrypt -sender QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st \
-recipients FXotuKi9YCkxbzQ1VSPgjU8uAeA8C9y1nHdTKjdkuuj8,QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st > image.png.enc
```

## `keys decrypt`

Decrypt from (from stdin).

```shell
cat msg.enc | keys decrypt -armor
My secret 🤓
```

Decrypt image.png.enc to image.png.

```shell
keys decrypt -in image.png.enc -out image.png
```
