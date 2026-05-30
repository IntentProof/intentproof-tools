#!/usr/bin/env bash
# Validate contrib/oss-fuzz/intentproof project files and pin consistency.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="${ROOT}/contrib/oss-fuzz/intentproof"

required=(
  project.yaml
  Dockerfile
  build.sh
  pins.env
  README.md
)

for file in "${required[@]}"; do
  if [[ ! -f "${PROJECT}/${file}" ]]; then
    echo "missing OSS-Fuzz project file: ${PROJECT}/${file}" >&2
    exit 1
  fi
done

# shellcheck source=/dev/null
source "${PROJECT}/pins.env"

normalize_sha() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

for var in TOOLS_REF SPEC_REF CORE_REF; do
  val="${!var}"
  if ! echo "$val" | grep -qE '^[0-9a-fA-F]{40}$'; then
    echo "invalid ${var}: must be a 40-character hex SHA, got '${val}'" >&2
    exit 1
  fi
done

for var in TOOLS_REF SPEC_REF CORE_REF; do
  val="${!var}"
  if ! grep -q "$val" "${PROJECT}/Dockerfile"; then
    echo "Dockerfile missing pin ${var}=${val}" >&2
    exit 1
  fi
done

if grep -q 'compile_go_fuzzer' "${PROJECT}/build.sh"; then
  echo "build.sh must use compile_native_go_fuzzer for native Go fuzz tests" >&2
  exit 1
fi

if ! grep -q 'compile_native_go_fuzzer' "${PROJECT}/build.sh"; then
  echo "build.sh missing compile_native_go_fuzzer invocations" >&2
  exit 1
fi

spec_dir="${INTENTPROOF_SPEC_DIR:-}"
if [[ -n "$spec_dir" && -f "$spec_dir/compatibility/pins.v1.json" ]]; then
  pins_file="$spec_dir/compatibility/pins.v1.json"
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required to compare OSS-Fuzz pins with $pins_file" >&2
    exit 1
  fi
  expected_tools="$(normalize_sha "$(jq -r '.entries[] | select(.ref_kind=="oss_fuzz_tools_ref") | .sha' "$pins_file")")"
  expected_spec="$(normalize_sha "$(jq -r '.spec_ref' "$pins_file")")"
  expected_core="$(normalize_sha "$(jq -r '.entries[] | select(.ref_kind=="oss_fuzz_core_ref") | .sha' "$pins_file")")"
  actual_tools="$(normalize_sha "$TOOLS_REF")"
  actual_spec="$(normalize_sha "$SPEC_REF")"
  actual_core="$(normalize_sha "$CORE_REF")"
  if [[ "$actual_tools" != "$expected_tools" ]]; then
    echo "OSS-Fuzz TOOLS_REF ${actual_tools} does not match pins manifest ${expected_tools}" >&2
    exit 1
  fi
  if [[ "$actual_spec" != "$expected_spec" ]]; then
    echo "OSS-Fuzz SPEC_REF ${actual_spec} does not match pins manifest ${expected_spec}" >&2
    exit 1
  fi
  if [[ "$actual_core" != "$expected_core" ]]; then
    echo "OSS-Fuzz CORE_REF ${actual_core} does not match pins manifest ${expected_core}" >&2
    exit 1
  fi
  echo "PASS: OSS-Fuzz pins match ecosystem manifest"
fi

echo "PASS: OSS-Fuzz project files and pins validated"
