#!/usr/bin/env bash
# Overlay compatibility/pins.v1.json when pins bump commits trail SPEC_REF.
set -euo pipefail

spec_dir="${1:-intentproof-spec}"
branch="${PR_SIBLING_BRANCH:-}"

if [[ ! -d "$spec_dir/.git" ]]; then
  echo "spec checkout not found: $spec_dir" >&2
  exit 1
fi

sync_from_ref() {
  local ref="$1"
  git -C "$spec_dir" checkout "$ref" -- compatibility/pins.v1.json
}

if [[ -n "$branch" ]] && git -C "$spec_dir" fetch origin "$branch" 2>/dev/null; then
  sync_from_ref FETCH_HEAD
  exit 0
fi

git -C "$spec_dir" fetch origin main
sync_from_ref FETCH_HEAD
