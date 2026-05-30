#!/usr/bin/env bash
# Bundle verification profile gate: profile tests + counterparty golden verify.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SPEC_DIR="${1:-${INTENTPROOF_SPEC_DIR:-./intentproof-spec}}"
if [[ ! -f "$SPEC_DIR/golden/counterparty/counterparty-refund.proof.tar.zst" ]]; then
  echo "golden counterparty bundle not found at: $SPEC_DIR/golden/counterparty/" >&2
  exit 2
fi

echo "== bundle verification profile tests =="
go test ./pkg/bundle -run 'TestCreateEmbedsVerificationProfile|TestVerifyRejectsMissingVerificationProfile|TestVerifyRejectsUnsupportedVerifierVersion|TestVerifyRejectsRunIDMismatch|TestVerifyRejectsTamperedVerifierVersionInSignedBundle' -count=1

echo "== counterparty golden bundle verify =="
INTENTPROOF_SPEC_DIR="$(cd "$SPEC_DIR" && pwd)" \
  bash ./scripts/check-counterparty-golden.sh "$SPEC_DIR"

echo "PASS: bundle verification profile gate."
