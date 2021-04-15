#!/usr/bin/env bash

set -e -u -o pipefail # Fail on error

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$dir"

go install github.com/securego/gosec/v2/cmd/gosec
`go env GOPATH`/bin/gosec ./...
