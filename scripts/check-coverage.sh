#!/usr/bin/env bash

set -euo pipefail

PROFILE_PATH="${1:-coverage.out}"
MIN_COVERAGE="${2:-95}"

if [[ ! -f "$PROFILE_PATH" ]]; then
  echo "coverage profile not found: $PROFILE_PATH" >&2
  exit 2
fi

TOTAL_LINE="$(go tool cover -func="$PROFILE_PATH" | awk '/^total:/{print; exit}')"
if [[ -z "$TOTAL_LINE" ]]; then
  echo "unable to read total coverage from $PROFILE_PATH" >&2
  exit 2
fi

TOTAL_PERCENT="$(printf '%s' "$TOTAL_LINE" | awk '{print $3}' | tr -d '%')"

echo "Total coverage: ${TOTAL_PERCENT}%"
echo "Minimum required: ${MIN_COVERAGE}%"

if awk -v got="$TOTAL_PERCENT" -v min="$MIN_COVERAGE" 'BEGIN { exit !(got + 0 >= min + 0) }'; then
  echo "PASS: coverage threshold met"
  exit 0
fi

echo "FAIL: coverage threshold not met" >&2
exit 1
