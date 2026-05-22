#!/usr/bin/env bash
# Run platform fuzz gates: golden corpus replay and optional extended fuzz.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

resolve_checkout_dir() {
  local label="$1"
  local raw="$2"
  local candidate=""

  if [[ "$raw" == /* ]]; then
    candidate="$raw"
  else
    candidate="$ROOT/$raw"
  fi

  if [[ ! -d "$candidate" ]]; then
    echo "${label} not found: ${raw}" >&2
    exit 1
  fi

  (cd "$candidate" && pwd)
}

SPEC_DIR="$(resolve_checkout_dir "fuzz spec checkout" "${INTENTPROOF_SPEC_DIR:-./intentproof-spec}")"
CORE_DIR="$(resolve_checkout_dir "intentproof-core checkout" "${INTENTPROOF_CORE_DIR:-./intentproof-core}")"

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
  echo "intentproof-core ingest package not found under: $CORE_DIR" >&2
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

run_jcs_differential() {
  local node_dir python_dir
  node_dir="$(resolve_checkout_dir "node sdk checkout" "${INTENTPROOF_NODE_SDK_DIR:-../intentproof-sdk-node}")"
  python_dir="$(resolve_checkout_dir "python sdk checkout" "${INTENTPROOF_PYTHON_SDK_DIR:-../intentproof-sdk-python}")"

  if [[ ! -f "${node_dir}/dist/signing.js" ]]; then
    echo "building node sdk for jcs differential harness..."
    (cd "${node_dir}" && npm ci && npm run build)
  fi

  echo "Running cross-language JCS differential harness..."
  export INTENTPROOF_NODE_SDK_DIR="${node_dir}"
  export INTENTPROOF_PYTHON_SDK_DIR="${python_dir}"
  go test -count=1 ./cmd/jcs-differential-fuzz/
  go run ./cmd/jcs-differential-fuzz/ -iterations "${JCS_DIFF_ITERATIONS:-256}"
}

if [[ "${SKIP_JCS_DIFFERENTIAL:-}" == "1" ]]; then
  echo "SKIP: jcs differential harness (SKIP_JCS_DIFFERENTIAL=1)"
elif [[ -d "${INTENTPROOF_NODE_SDK_DIR:-$ROOT/../intentproof-sdk-node}" ]] \
  && [[ -d "${INTENTPROOF_PYTHON_SDK_DIR:-$ROOT/../intentproof-sdk-python}" ]]; then
  run_jcs_differential || {
    echo "jcs differential harness failed" >&2
    exit 1
  }
else
  echo "SKIP: jcs differential harness (node/python SDK checkouts not present)"
fi

echo "PASS: fuzz gate completed"
