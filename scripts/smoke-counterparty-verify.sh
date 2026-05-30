#!/usr/bin/env bash
# Smoke-test counterparty golden verification on the current OS/arch.
# Full three-OS matrix is manual; CI locks stdout via check-counterparty-golden.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC_DIR="${INTENTPROOF_SPEC_DIR:-$ROOT/../intentproof-spec}"

echo "Platform: $(uname -s)/$(uname -m)"
echo "Spec dir: $SPEC_DIR"

"$ROOT/scripts/check-counterparty-golden.sh" "$SPEC_DIR"

if command -v intentproof-verify >/dev/null 2>&1; then
  BUNDLE="$SPEC_DIR/golden/counterparty/counterparty-refund.proof.tar.zst"
  if [[ -f "$BUNDLE" ]]; then
    echo "--- installed intentproof-verify ---"
    intentproof-verify "$BUNDLE"
    intentproof-verify explain "$BUNDLE" | head -n 20
  fi
else
  echo "SKIP: intentproof-verify not on PATH (go test path above is sufficient for CI parity)"
fi

echo "PASS: counterparty smoke on $(uname -s)/$(uname -m)"
