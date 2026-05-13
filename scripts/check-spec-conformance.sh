#!/usr/bin/env bash

set -euo pipefail

SPEC_DIR="${1:-${INTENTPROOF_SPEC_DIR:-../intentproof-spec}}"

if [[ ! -f "$SPEC_DIR/schema/policy.v1.schema.json" ]]; then
  echo "spec schema not found at: $SPEC_DIR/schema/policy.v1.schema.json" >&2
  exit 2
fi

SPEC_DIR_ABS="$(cd "$SPEC_DIR" && pwd)"

INTENTPROOF_SPEC_DIR="$SPEC_DIR_ABS" \
  go test ./pkg/policy -run TestPolicyCompilerMatchesSpecSchema -count=1
