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

echo "PASS: OSS-Fuzz project files and pins validated"
