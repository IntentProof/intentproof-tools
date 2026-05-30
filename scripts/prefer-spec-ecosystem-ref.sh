#!/usr/bin/env bash
# Prefer intentproof-spec ecosystem branch when pins-aligned checkout lacks
# bundle verification profile goldens (coordinated PR review window).
set -euo pipefail

SPEC_DIR="${1:-intentproof-spec}"
BRANCH="${2:-phase4-ecosystem-adapter-bundle}"

if [[ ! -d "$SPEC_DIR/compatibility" ]]; then
  echo "spec checkout not found: $SPEC_DIR" >&2
  exit 1
fi

if grep -q 'verification_profile' "$SPEC_DIR/schema/bundle-manifest.v1.schema.json" 2>/dev/null; then
  exit 0
fi

git -C "$SPEC_DIR" fetch origin "$BRANCH" 2>/dev/null || exit 0
git -C "$SPEC_DIR" checkout FETCH_HEAD
