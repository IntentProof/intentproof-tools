#!/usr/bin/env bash
set -euo pipefail

if ! command -v nfpm >/dev/null 2>&1; then
  printf 'nfpm is required to build RPM packages.\n' >&2
  printf 'Install it with: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.46.3\n' >&2
  exit 1
fi

version="${RELEASE_VERSION:-0.0.0-dev}"
version="${version#v}"
commit="${RELEASE_COMMIT:-$(git rev-parse HEAD)}"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
release_date="${RELEASE_DATE:-$(python3 -c 'import datetime, sys; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$source_date_epoch")}"
output_dir="${RPM_REPO_OUTPUT_DIR:-dist/rpm}"
work_dir="${RPM_REPO_WORK_DIR:-dist/rpm-work}"
fedora_current="${FEDORA_CURRENT:-42}"
fedora_previous="${FEDORA_PREVIOUS:-41}"

rm -rf "$output_dir" "$work_dir"
mkdir -p "$work_dir"

build_package() {
  local name="$1"
  local cmd="./cmd/$1"
  local arch="$2"
  local nfpm_arch="$3"
  local rpm_arch="$4"
  local description="$5"
  local root="$work_dir/root-$name-$nfpm_arch"
  local config="$work_dir/$name-$nfpm_arch.nfpm.yaml"
  local artifact_dir="$work_dir/packages/$rpm_arch"

  rm -rf "$root"
  mkdir -p "$root/usr/bin" "$artifact_dir"

  GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -buildid= -X github.com/intentproof/intentproof-tools/pkg/buildinfo.Version=$version -X github.com/intentproof/intentproof-tools/pkg/buildinfo.Commit=$commit -X github.com/intentproof/intentproof-tools/pkg/buildinfo.Date=$release_date" \
    -o "$root/usr/bin/$name" \
    "$cmd"

  cat > "$config" <<EOF
name: $name
arch: $nfpm_arch
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
    --packager rpm \
    --target "$artifact_dir"
}

for arch_pair in "amd64 amd64 x86_64" "arm64 arm64 aarch64"; do
  read -r go_arch nfpm_arch rpm_arch <<< "$arch_pair"
  build_package intentproof "$go_arch" "$nfpm_arch" "$rpm_arch" \
    "IntentProof developer CLI for local proofs and policy workflows."
  build_package intentproof-verify "$go_arch" "$nfpm_arch" "$rpm_arch" \
    "IntentProof offline verifier for proof bundles."
done

repo_paths=(
  "rhel/8/x86_64"
  "rhel/8/aarch64"
  "rhel/9/x86_64"
  "rhel/9/aarch64"
  "fedora/$fedora_current/x86_64"
  "fedora/$fedora_current/aarch64"
  "fedora/$fedora_previous/x86_64"
  "fedora/$fedora_previous/aarch64"
  "opensuse/leap/15/x86_64"
  "opensuse/leap/15/aarch64"
)

for repo_path in "${repo_paths[@]}"; do
  rpm_arch="${repo_path##*/}"
  target_dir="$output_dir/$repo_path"
  mkdir -p "$target_dir"
  cp "$work_dir/packages/$rpm_arch"/*.rpm "$target_dir/"
done

python3 ./scripts/render-rpm-metadata.py \
  --repo-root "$output_dir" \
  --repo-path "${repo_paths[@]}"

printf 'PASS: RPM repository layout written to %s\n' "$output_dir"
