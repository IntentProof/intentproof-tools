#!/usr/bin/env bash
set -euo pipefail

repo_root="${RPM_REPO_ROOT:-dist/rpm}"
kms_key_id="${INTENTPROOF_PKG_SIGN_KMS_KEY_ID:?INTENTPROOF_PKG_SIGN_KMS_KEY_ID is required}"
created_at="${INTENTPROOF_PKG_SIGN_CREATED_AT:?INTENTPROOF_PKG_SIGN_CREATED_AT is required}"
pkg_sign="${RPM_PKG_SIGN_BIN:-./dist/intentproof-pkg-sign}"
public_key_path="$repo_root/intentproof.gpg"

if [[ ! -d "$repo_root" ]]; then
  printf 'missing RPM repository root: %s\n' "$repo_root" >&2
  exit 1
fi

export AWS_REGION="${AWS_REGION:-us-east-1}"

"$pkg_sign" export-public-key \
  --kms-key-id "$kms_key_id" \
  --created-at "$created_at" \
  --output "$public_key_path"

mapfile -t repomd_paths < <(find "$repo_root" -path '*/repodata/repomd.xml' | sort)
if ((${#repomd_paths[@]} == 0)); then
  printf 'no repomd.xml files found under %s\n' "$repo_root" >&2
  exit 1
fi

verify_home=""
if command -v gpg >/dev/null 2>&1; then
  verify_home="$(mktemp -d)"
  chmod 700 "$verify_home"
  gpg --homedir "$verify_home" --batch --no-tty --import "$public_key_path"
fi

for repomd_path in "${repomd_paths[@]}"; do
  signature_path="${repomd_path}.asc"
  "$pkg_sign" sign \
    --kms-key-id "$kms_key_id" \
    --created-at "$created_at" \
    --output "$signature_path" \
    "$repomd_path"
  if [[ -n "$verify_home" ]]; then
    gpg --homedir "$verify_home" --batch --no-tty --verify "$signature_path" "$repomd_path"
  fi
done

if [[ -n "$verify_home" ]]; then
  rm -rf "$verify_home"
fi

printf 'PASS: signed RPM metadata in %s (%d repositories)\n' \
  "$repo_root" "${#repomd_paths[@]}"
