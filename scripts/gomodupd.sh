#!/usr/bin/env bash

set -e -u -o pipefail # Fail on error

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $dir/..

gomodupd () {
    cd $1
    go get -u
    go test
    git add go.mod go.sum
    cd ..
}

for dir in keyring saltpack
do
    gomodupd $dir
done
