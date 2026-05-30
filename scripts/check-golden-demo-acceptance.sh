#!/usr/bin/env bash
# Task 6.8 acceptance: offline refund demo timing, findings, and bundle re-verify.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SPEC_DIR="${INTENTPROOF_SPEC_DIR:-./intentproof-spec}"
if [[ ! -d "$SPEC_DIR/golden/demo" ]]; then
  echo "golden/demo not found under: $SPEC_DIR" >&2
  echo "Set INTENTPROOF_SPEC_DIR or checkout intentproof-spec at SPEC_REF." >&2
  exit 2
fi

export INTENTPROOF_SPEC_DIR="$(cd "$SPEC_DIR" && pwd)"
export INTENTPROOF_LOCAL_OPEN_BROWSER=0

echo "Golden demo acceptance (spec=$INTENTPROOF_SPEC_DIR)..."

go test ./pkg/demo -run TestRefundDemoAcceptance -count=1 -timeout 130s
go test ./cmd/intentproof -run 'TestCLIRefundDemoAndVerifyBundle|TestRunDemoRefundCommand' -count=1 -timeout 130s

echo "PASS: golden demo refund acceptance ($(uname -s)/$(uname -m))."
