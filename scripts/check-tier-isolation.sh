#!/usr/bin/env bash
# Enforce ADR-010 dependency invariant:
#   Tier 1 (this repo, Apache 2.0) MUST NOT import Tier 2 code.
#
# Tier 2 = github.com/intentproof/intentproof-core/...
#
# This is the load-bearing license-laundering guard. Do not weaken
# without revisiting ADR-010.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

violations="$(grep -rEn \
    --include='*.go' \
    '"github\.com/intentproof/intentproof-core(/|")' \
    . 2>/dev/null || true)"

if [[ -n "$violations" ]]; then
    echo "ADR-010 violation: Tier 1 (intentproof-tools) must not import Tier 2 (intentproof-core)." >&2
    echo "" >&2
    echo "Offending imports:" >&2
    echo "$violations" >&2
    exit 1
fi

echo "PASS: no Tier 2 imports detected in intentproof-tools."
