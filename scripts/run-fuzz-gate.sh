#!/usr/bin/env bash
# Run platform fuzz gates: golden corpus replay and optional extended fuzz.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SPEC_DIR="${INTENTPROOF_SPEC_DIR:-./intentproof-spec}"
if [[ "$SPEC_DIR" != /* ]]; then
  SPEC_DIR="$(cd "$ROOT" && cd "$SPEC_DIR" && pwd)"
else
  SPEC_DIR="$(cd "$SPEC_DIR" && pwd)"
fi

CORE_DIR="${INTENTPROOF_CORE_DIR:-./intentproof-core}"
if [[ "$CORE_DIR" != /* ]]; then
  CORE_DIR="$(cd "$ROOT" && cd "$CORE_DIR" && pwd)"
else
  CORE_DIR="$(cd "$CORE_DIR" && pwd)"
fi

for corpus in canon verifier bundle policy ingest; do
  if [[ ! -d "$SPEC_DIR/golden/fuzz-corpora/$corpus" ]]; then
    echo "fuzz corpus not found: $SPEC_DIR/golden/fuzz-corpora/$corpus" >&2
    exit 1
  fi
done

export INTENTPROOF_SPEC_DIR="$SPEC_DIR"

echo "Running spec golden corpora and fuzz seed replay..."
go test -count=1 ./pkg/canon/ -run='^(TestMarshalRawSpecCorpus|FuzzMarshalRaw)$'
go test -count=1 ./pkg/verifier/ -run='^(TestVerifySpecCorpus|FuzzVerify)$'
go test -count=1 ./pkg/bundle/ -run='^(TestBundleVerifySpecCorpus|FuzzBundleVerify)$'
go test -count=1 ./pkg/policy/ -run='^(TestCompileSpecCorpus|FuzzCompile)$'

if [[ ! -d "$CORE_DIR/pkg/ingest" ]]; then
  echo "intentproof-core checkout not found: $CORE_DIR" >&2
  exit 1
fi
(
  cd "$CORE_DIR"
  export INTENTPROOF_SPEC_DIR="$SPEC_DIR"
  go test -count=1 ./pkg/ingest/ -run='^(TestParseExecutionEventSpecCorpus|FuzzParseExecutionEvent)$'
)

if [[ -n "${FUZZ_TIME:-}" ]]; then
  if ! [[ "$FUZZ_TIME" =~ ^[0-9]+([smh]|ms|us|ns)$ ]]; then
    echo "invalid FUZZ_TIME (expected Go duration, e.g. 30m): $FUZZ_TIME" >&2
    exit 1
  fi
  targets=(
    "./pkg/canon/:FuzzMarshalRaw"
    "./pkg/verifier/:FuzzVerify"
    "./pkg/bundle/:FuzzBundleVerify"
    "./pkg/policy/:FuzzCompile"
  )
  for target in "${targets[@]}"; do
    pkg="${target%%:*}"
    fuzz="${target##*:}"
    echo "Running ${fuzz} extended fuzz for ${FUZZ_TIME}..."
    go test -count=1 "$pkg" -run='^$' -fuzz="$fuzz" -fuzztime="$FUZZ_TIME"
  done
  (
    cd "$CORE_DIR"
    export INTENTPROOF_SPEC_DIR="$SPEC_DIR"
    echo "Running FuzzParseExecutionEvent extended fuzz for ${FUZZ_TIME}..."
    go test -count=1 ./pkg/ingest/ -run='^$' -fuzz=FuzzParseExecutionEvent -fuzztime="$FUZZ_TIME"
  )
fi

echo "PASS: fuzz gate completed"
