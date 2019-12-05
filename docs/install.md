# Install

To manually build the binaries, see [Building From Source](building.md).

## macOS

To install via [homebrew](https://brew.sh/):

```shell
brew tap keys-app/tap
brew install keys-app/tap/keys
```

## Windows

To install via [scoop](https://scoop.sh/):

```shell
scoop bucket add app https://github.com/keys-app/scoop-bucket
scoop install keys
```

## Linux

Add keys.app apt repository:

```shell
echo "deb https://storage.googleapis.com/aptly.keys.app current main" \
    | sudo tee -a /etc/apt/sources.list.d/keys.list
```

Add the keys apt signing public key:

```shell
wget -qO - https://storage.googleapis.com/aptly.keys.app/keys.asc | sudo apt-key add -
```

```shell
sudo apt-get update
sudo apt-get install keys
```
