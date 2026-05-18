#!/usr/bin/env bash
set -euo pipefail

if ! command -v nfpm >/dev/null 2>&1; then
  printf 'nfpm is required to build Debian packages.\n' >&2
  printf 'Install it with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.46.3\n' >&2
  exit 1
fi

version="${RELEASE_VERSION:-0.0.0-dev}"
version="${version#v}"
commit="${RELEASE_COMMIT:-$(git rev-parse HEAD)}"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
release_date="${RELEASE_DATE:-$(python3 -c 'import datetime, sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$source_date_epoch")}"
output_dir="${APT_REPO_OUTPUT_DIR:-dist/apt}"
work_dir="${APT_REPO_WORK_DIR:-dist/apt-work}"
suite="${APT_REPO_SUITE:-stable}"
codename="${APT_REPO_CODENAME:-stable}"
component="${APT_REPO_COMPONENT:-main}"

rm -rf "$output_dir" "$work_dir"
mkdir -p "$output_dir/pool/$component/i" "$work_dir"

build_package() {
  local name="$1"
  local cmd="./cmd/$1"
  local arch="$2"
  local deb_arch="$3"
  local description="$4"
  local root="$work_dir/root-$name-$deb_arch"
  local config="$work_dir/$name-$deb_arch.nfpm.yaml"
  local target_dir="$output_dir/pool/$component/i/$name"

  rm -rf "$root"
  mkdir -p "$root/usr/bin" "$target_dir"

  GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -buildid= -X github.com/intentproof/intentproof-tools/pkg/buildinfo.Version=$version -X github.com/intentproof/intentproof-tools/pkg/buildinfo.Commit=$commit -X github.com/intentproof/intentproof-tools/pkg/buildinfo.Date=$release_date" \
    -o "$root/usr/bin/$name" \
    "$cmd"

  cat > "$config" <<EOF
name: $name
arch: $deb_arch
platform: linux
version: $version
section: utils
priority: optional
maintainer: IntentProof Release Bot <release-bot@intentproof.io>
vendor: IntentProof
homepage: https://intentproof.io
license: Apache-2.0
description: $description
contents:
  - src: $root/usr/bin/$name
    dst: /usr/bin/$name
    file_info:
      mode: 0755
EOF

  SOURCE_DATE_EPOCH="$source_date_epoch" nfpm package \
    --config "$config" \
    --packager deb \
    --target "$target_dir/${name}_${version}_${deb_arch}.deb"
}

for arch in amd64 arm64; do
  build_package intentproof "$arch" "$arch" \
    "IntentProof developer CLI for local proofs and policy workflows."
  build_package intentproof-verify "$arch" "$arch" \
    "IntentProof offline verifier for proof bundles."
done

python3 ./scripts/render-apt-metadata.py \
  --repo-root "$output_dir" \
  --suite "$suite" \
  --codename "$codename" \
  --component "$component" \
  --architectures amd64 arm64

printf 'PASS: apt repository layout written to %s\n' "$output_dir"
