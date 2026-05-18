#!/usr/bin/env bash
set -euo pipefail

repo_root="${APT_REPO_ROOT:-dist/apt}"
codename="${APT_REPO_CODENAME:-stable}"
kms_key_id="${INTENTPROOF_PKG_SIGN_KMS_KEY_ID:?INTENTPROOF_PKG_SIGN_KMS_KEY_ID is required}"
created_at="${INTENTPROOF_PKG_SIGN_CREATED_AT:?INTENTPROOF_PKG_SIGN_CREATED_AT is required}"
pkg_sign="${APT_PKG_SIGN_BIN:-./dist/intentproof-pkg-sign}"

release_path="$repo_root/dists/$codename/Release"
public_key_path="$repo_root/intentproof.gpg"
release_sig_path="$repo_root/dists/$codename/Release.gpg"

if [[ ! -f "$release_path" ]]; then
  printf 'missing Release file: %s\n' "$release_path" >&2
  exit 1
fi

export AWS_REGION="${AWS_REGION:-us-east-1}"

"$pkg_sign" export-public-key \
  --kms-key-id "$kms_key_id" \
  --created-at "$created_at" \
  --output "$public_key_path"

"$pkg_sign" sign \
  --kms-key-id "$kms_key_id" \
  --created-at "$created_at" \
  --output "$release_sig_path" \
  "$release_path"

if command -v gpg >/dev/null 2>&1; then
  verify_home="$(mktemp -d)"
  chmod 700 "$verify_home"
  gpg --homedir "$verify_home" --batch --no-tty --import "$public_key_path"
  gpg --homedir "$verify_home" --batch --no-tty --verify "$release_sig_path" "$release_path"
  rm -rf "$verify_home"
fi

printf 'PASS: signed apt metadata in %s\n' "$repo_root"
