# Search

## `keys search`

Search.

```shell
keys search
```

Outputs key ID, name@service.

```text
EHpp3JTDbDYJgziKxCcMuC54SkJL2yPH2Ubk3RzmNZam gabriel@github 🔑
9bT3eNgzxWAgjgGRhDyeaMGXxT2KXLHYPFdA9GneQuuN
M3xBgcqgdkVcM2Q47142o48ARP2ZtvWfh16FULMEATc3
MYoYxCfwF4ZwhkpzQZC6FYqk9EDshSgjWq4LvhL24YrN
QhMMo4xL9Ugr629mNrGy2Bky9Q6KKkfpoXDe8m8T1yHc
XzLCnBfs6igGqEZsjvuHRF6ioy9knLm5fkLf1eZU75eP
ZZRiTbGP4VwnUqraBYZfJRHhvy2oi7ea5ABDteLA2myP
```

Search with a user.

```shell
keys search -q gabriel
```

Outputs key ID, name, service.

```text
GCyz8QoBP3tw3YzHMguLxoJJ8gKdYoLJbBE2PWkphGMm gabriel@github
```

Search for a key id.

```shell
keys search -q 6bZHKyq
```

Outputs key IDs with the correpsonding user.

```text
6bZHKyqrzg1hEZF6wehf4SL56c2qzv5vcdfwwba6j1kD
```
