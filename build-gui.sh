#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

# Requires gcc plus the Fyne platform graphics development dependencies.
command -v gcc >/dev/null 2>&1 || {
  echo "Error: gcc was not found in PATH." >&2
  exit 1
}

CGO_ENABLED=1 go build -o lpe-checker-gui ./cmd/lpe-checker-gui
echo "Built lpe-checker-gui"

