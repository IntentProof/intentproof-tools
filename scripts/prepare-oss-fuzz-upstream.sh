#!/usr/bin/env bash
# Copy contrib/oss-fuzz/intentproof into a google/oss-fuzz clone.
# Usage: prepare-oss-fuzz-upstream.sh <path-to-oss-fuzz-repo>
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <oss-fuzz-clone-dir>" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$(cd "$1" && pwd)"
SRC="${ROOT}/contrib/oss-fuzz/intentproof"
TARGET="${DEST}/projects/intentproof"

if [[ ! -d "${DEST}/infra" ]]; then
  echo "not an oss-fuzz checkout (missing infra/): ${DEST}" >&2
  exit 1
fi

bash "${ROOT}/scripts/check-oss-fuzz-project.sh"

mkdir -p "${TARGET}"
cp "${SRC}/project.yaml" "${SRC}/Dockerfile" "${SRC}/build.sh" "${TARGET}/"
chmod +x "${TARGET}/build.sh"

echo "Copied OSS-Fuzz project to ${TARGET}"
echo "Next: cd ${DEST} && git add projects/intentproof && git commit"
