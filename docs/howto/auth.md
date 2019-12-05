# Auth

By default, clients (including the keys command line client) must be authorized
to use the service. This prevents other programs on your system from accessing
the service without permission.

```shell
keys auth
```

After entering your password, the client will create an auth token to use.
This auth token is only valid for a limited amount of time.

```text
export KEYS_AUTH="AbGNXgc4aK9x1b1pHlOLZ33meXyv796DyWK5jHqiS1R"
# To output an auth token:
#  keys auth -token
#
# To include in a shell environment:
#  export KEYS_AUTH=`keys auth -token`
#
# or using eval:
#  eval $(keys auth)
#
# For Powershell:
#  $env:KEYS_AUTH = (keys auth -token)
```

## Setup

The first time you run `keys auth` you can setup your key.

```shell
keys auth
```

```text
Would you like to setup a new key or use an existing one?
(n) New key
(e) Existing key
n

OK, let's create a password.
Create a password:
Re-enter the password:

Now you'll need to backup a (secret) recovery phrase. This phrase by itself
can't be used by itself to access your account. A good way to backup this phrase
is to email it to yourself or save it in the cloud in a place only you can
access. This allows you to recover your account if your devices go missing.

Your recovery phrase is:

curtain dog doll quiz leave mass saddle patch spirit pulp decide town coin uncle
clean hip job gun deal grit hover absurd scrub total

Have you backed up this recovery phrase (y/n)? y
Do you want to publish your public key to the key server (api.keys.app) (Y/n)?

Saving...
Saved key V71SnjJ1JsqsNJj5Xt1atq4VMH5cYNorCPsgk63ZuUGa
```
