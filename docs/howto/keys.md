# Keys

## `keys keys`

List keys.

Private keys have a 🔑 type.

```shell
keys keys
```

Outputs key ID, user name@service, and key type.

```text
EHpp3JTDbDYJgziKxCcMuC54SkJL2yPH2Ubk3RzmNZam gabriel@github 🔑
9bT3eNgzxWAgjgGRhDyeaMGXxT2KXLHYPFdA9GneQuuN
M3xBgcqgdkVcM2Q47142o48ARP2ZtvWfh16FULMEATc3
MYoYxCfwF4ZwhkpzQZC6FYqk9EDshSgjWq4LvhL24YrN
QhMMo4xL9Ugr629mNrGy2Bky9Q6KKkfpoXDe8m8T1yHc
XzLCnBfs6igGqEZsjvuHRF6ioy9knLm5fkLf1eZU75eP
ZZRiTbGP4VwnUqraBYZfJRHhvy2oi7ea5ABDteLA2myP
```

## `keys pull`

Pull a public key (sigchain) from a key server.

```shell
keys pull -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st
```

Outputs key ID.

```text
QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st
```

Pull a public key (sigchain) from a key server for a user.

```shell
keys pull -user gabriel@github
```

Outputs key ID.

```text
QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st
```

Pull all sigchains from the key server.

```shell
keys pull -all
```

Outputs key IDs.

```text
QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st
1ZPVF5jYZ88Smawag4Vk4Gpw4jKaL8Ta6urfHnzG7LVi
D7EBPvt6DGJrwFXY3tg87doqWp11XnyxQg2823aomWQ4
UEpsSLAvGdjr83aEzPbS7ACiqn3XCix2YPSQeg8sLScZ
```

## `keys push`

Publish a public key (sigchain) to a key server.

```shell
keys push -kid QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st
```

Outputs remote sigchain locations.

```text
https://keys.pub/sigchain/QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st/1
https://keys.pub/sigchain/QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st/2
```

## `keys key show`

Show key information.

```shell
keys key show -kid Ra7SP5hKb1YyABgPCNQGRTmozm6dd9bJ2iRNFTX7iJ7t
```

Shows kid, user and type.

```text
Ra7SP5hKb1YyABgPCNQGRTmozm6dd9bJ2iRNFTX7iJ7t  🔑
```

## `keys key generate`

Create a key and publish it.

```shell
keys key generate -publish
```

Outputs the key ID.

```text
Etwmp3KzSyqBsAEUBjxE4pQq4zFvLByg794xEt44YDmU
```

## `keys key remove`

Remove a key or user public key. Specify a -seed-phrase to confirm the removal.

```shell
keys key remove -seed-phrase "victory before seminar agree swamp aware cage oppose escape tube gloom donkey claw slot spy search coast mind pride mask guard bench entry mosquito" \
-kid Etwmp3KzSyqBsAEUBjxE4pQq4zFvLByg794xEt44YDmU
```

## `keys key backup`

Get a backup seed phrase for a key.

```shell
keys key backup -kid Etwmp3KzSyqBsAEUBjxE4pQq4zFvLByg794xEt44YDmU
```

Outputs seed phrase.

```txt
victory before seminar agree swamp aware cage oppose escape tube gloom donkey claw slot spy search coast mind pride mask guard bench entry mosquito
```

## `keys key recover`

Import a key from a seed phase.

```shell
keys key recover -seed-phrase "victory before seminar agree swamp aware cage oppose escape tube gloom donkey claw slot spy search coast mind pride mask guard bench entry mosquito"
```

Outputs key ID.

```txt
Etwmp3KzSyqBsAEUBjxE4pQq4zFvLByg794xEt44YDmU
```
