#!/usr/bin/env bash
# CI-parity coverage gate for local checkpoints and manual runs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

resolve_spec_dir() {
  local raw="${INTENTPROOF_SPEC_DIR:-}"
  local candidate=""

  if [[ -n "$raw" ]]; then
    if [[ "$raw" == /* ]]; then
      candidate="$raw"
    else
      candidate="$ROOT/$raw"
    fi
    if [[ -d "$candidate" ]]; then
      (cd "$candidate" && pwd)
      return 0
    fi
    echo "INTENTPROOF_SPEC_DIR not found: $raw" >&2
    exit 2
  fi

  for candidate in "$ROOT/intentproof-spec" "$ROOT/../intentproof-spec"; do
    if [[ -d "$candidate" ]]; then
      (cd "$candidate" && pwd)
      return 0
    fi
  done

  echo "intentproof-spec checkout not found; set INTENTPROOF_SPEC_DIR" >&2
  exit 2
}

SPEC_ABS="$(resolve_spec_dir)"
export INTENTPROOF_SPEC_DIR="$SPEC_ABS"
export INTENTPROOF_LOCAL_OPEN_BROWSER=0

GOWORK=off go build ./...

mapfile -t PACKAGES < <(
  go list ./... \
    | grep -v '/cmd/local-seed$' \
    | grep -v '/cmd/jcs-differential-fuzz$'
)
GOWORK=off go test -count=1 -coverprofile=coverage.out -covermode=atomic "${PACKAGES[@]}"
bash ./scripts/check-coverage.sh coverage.out
