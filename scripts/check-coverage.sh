#!/usr/bin/env bash
# Verify total statement coverage from a go cover profile.
# Usage: check-coverage.sh [profile] [min_percent]
# Default profile: coverage.out. Default minimum: 95%.

set -euo pipefail

PROFILE_PATH="${1:-coverage.out}"
MIN_COVERAGE="${2:-95}"

if [[ ! -f "$PROFILE_PATH" ]]; then
  echo "coverage profile not found: $PROFILE_PATH" >&2
  exit 2
fi

read -r COVERED TOTAL <<EOF
$(awk 'BEGIN { covered=0; total=0 }
     NR>1 { stmts=$(NF-1); cnt=$NF; total+=stmts; if (cnt>0) covered+=stmts }
     END { print covered, total }' "$PROFILE_PATH")
EOF

if [[ -z "$TOTAL" || "$TOTAL" -eq 0 ]]; then
  echo "unable to read total coverage from $PROFILE_PATH" >&2
  exit 2
fi

DISPLAY_PERCENT="$(awk -v c="$COVERED" -v t="$TOTAL" 'BEGIN { printf "%.1f", 100*c/t }')"

echo "Total coverage: ${DISPLAY_PERCENT}% (${COVERED}/${TOTAL} statements)"
echo "Minimum required: ${MIN_COVERAGE}%"

if awk -v c="$COVERED" -v t="$TOTAL" -v min="$MIN_COVERAGE" \
  'BEGIN { exit !(c * 100 >= t * min) }'; then
  echo "PASS: coverage threshold met"
  exit 0
fi

echo "FAIL: coverage threshold not met" >&2
exit 1
