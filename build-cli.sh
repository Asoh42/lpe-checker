#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

CGO_ENABLED=0 go build -o lpe-checker-cli ./cmd/lpe-checker-cli
echo "Built lpe-checker-cli"

