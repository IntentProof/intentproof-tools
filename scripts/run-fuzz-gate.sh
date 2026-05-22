#!/usr/bin/env bash
# Run the JCS canonicalizer fuzz gate: golden corpus replay and optional fuzz.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SPEC_DIR="${INTENTPROOF_SPEC_DIR:-./intentproof-spec}"
if [[ "$SPEC_DIR" != /* ]]; then
  SPEC_DIR="$(cd "$ROOT" && cd "$SPEC_DIR" && pwd)"
else
  SPEC_DIR="$(cd "$SPEC_DIR" && pwd)"
fi
CORPUS_DIR="$SPEC_DIR/golden/fuzz-corpora/canon"
if [[ ! -d "$CORPUS_DIR" ]]; then
  echo "fuzz corpus not found: $CORPUS_DIR" >&2
  exit 1
fi

export INTENTPROOF_SPEC_DIR="$SPEC_DIR"

echo "Running spec golden corpus and FuzzMarshalRaw seeds..."
go test -count=1 ./pkg/canon/ -run='^(TestMarshalRawSpecCorpus|FuzzMarshalRaw)$'

if [[ -n "${FUZZ_TIME:-}" ]]; then
  echo "Running FuzzMarshalRaw extended fuzz for ${FUZZ_TIME}..."
  go test -count=1 ./pkg/canon/ -run='^$' -fuzz=FuzzMarshalRaw -fuzztime="$FUZZ_TIME"
fi

echo "PASS: fuzz gate completed"
