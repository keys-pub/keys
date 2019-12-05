# Users

## `keys user setup`

```shell
What's the service?
(g) Github
(t) Twitter
t

What's your Twitter handle? boboloblaw

Save the following signed message as a tweet on your Twitter account.
https://twitter.com/intent/tweet

BEGIN MESSAGE.
eb90A0en2hcwfYi jYDez0uArQs3HYg OiJlOgVUIfSeips u7JJcO6819zwug6
n9639e2e18gwZtM CQlePtNVn9wTCKq LPKyEa7sfoHfnVB 0hPvyKMbyjBGqHh
7dz327KuwGT7Oww kMEmgjibmwuK6N3 1UwmaFLcDXRyz4c 7NV5uSV1Msu2Kjb
MiH1JUIqH80eo7u x6O3uRXcb5Shhfq MJx.
END MESSAGE.

Have you posted the signed message (Y/n)? Y
What's the location (URL) on github.com where the signed message was saved? https://twitter.com/boboloblaw/status/1181685633732898816

User successfully setup.
```

## `keys user sign`

Create signed statement for service user, linking key QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st to gabriel@github.

```shell
keys user sign -kid "QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st" \
-service "github" -name "gabriel"
```

Outputs signed statement.

```txt
BEGIN MESSAGE.
6C7cjOwfS25pYjf ykSIvIk1cHf5d3G ffL09Puva7QKTYq AOIVZnd7N1B23T3
biMftdYkd4LwOXP hGQkwcONSKtTCKs gwSpYAiSWCPT9aL xOi6m8aukRziLhy
6zRw0eOntOIeF4I JQZvA7PVC2cJdan K9eCUmoVaUKLqsb v91bARw0FcF62QB
QA5HdBgu10Qrl.
END MESSAGE.
```

Post this to a gist (if on github) or tweet (if on twitter) and run `keys user add` with the url to save it to the sigchain.

## `keys user add`

Verify signed statement at URL and save to sigchain.

```shell
keys user add -kid "QBrbzCWK5Mf5fzzFayCqV4fnZaGUTMRjvAxyEqf388st" \
-service "github" -name "gabriel" \
-url "https://gist.github.com/gabriel/01ce43aa867aa3b0105a6d18be7c98f6"
```
