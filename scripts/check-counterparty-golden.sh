#!/usr/bin/env bash
# Verify intentproof-verify stdout for the counterparty golden bundle.
set -euo pipefail

SPEC_DIR="${1:-${INTENTPROOF_SPEC_DIR:-./intentproof-spec}}"

if [[ ! -f "$SPEC_DIR/golden/counterparty/counterparty-refund.proof.tar.zst" ]]; then
  echo "golden counterparty bundle not found at: $SPEC_DIR/golden/counterparty/" >&2
  exit 2
fi
if [[ ! -f "$SPEC_DIR/golden/counterparty/expected-verify-stdout-sha256.txt" ]]; then
  echo "expected stdout hash not found under: $SPEC_DIR/golden/counterparty/" >&2
  exit 2
fi

SPEC_DIR_ABS="$(cd "$SPEC_DIR" && pwd)"

INTENTPROOF_SPEC_DIR="$SPEC_DIR_ABS" \
  go test ./cmd/intentproof-verify -run TestGoldenCounterpartyVerifyStdout -count=1

echo "PASS: counterparty golden verify stdout matches expected sha256."
