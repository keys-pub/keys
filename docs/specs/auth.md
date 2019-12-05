# Auth

When setting up authentication for the first time, we create a master key.

This master key is derived using a user supplied password (10 characters or more), combined with a secret 256-bit secret
recovery phrase (pepper).

We use the Argon2id KDF with this password and recovery phrase (pepper) with the following parameters:

```go
seed := argon2.IDKey(password, recoveryPhrase, 1, 64*1024, 4, 32)
```

This seed value is then used to create a master [Key](key.md) capable of signing and encryption.

If the user forgets either their password or their recovery phrase, they will not be able to recover their account.

After setting up the account, we also use this password (and a seperate salt value also with the Argon2id KDF) to
encrypt secrets added to the keyring. This provides additional protection, especially on platforms such as Windows and
Linux, where keyring access is not protected by the OS.

The password is never stored on disk and is only used to unlock access to the application. When the app starts the user
is required to re-enter their password. This password is combined with a salt to generate a key. This key only exists
in memory and is used to encrypt/decrypt keyring items. All keyring items are encrypted using this key, except for a the
salt.
