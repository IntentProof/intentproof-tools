#!/usr/bin/env bash
set -euo pipefail

repo_root="${APT_REPO_ROOT:-dist/apt}"
bucket="${APT_REPO_S3_BUCKET:?APT_REPO_S3_BUCKET is required}"
distribution_id="${APT_CLOUDFRONT_DISTRIBUTION_ID:?APT_CLOUDFRONT_DISTRIBUTION_ID is required}"

if [[ ! -d "$repo_root" ]]; then
  printf 'missing apt repository root: %s\n' "$repo_root" >&2
  exit 1
fi

aws s3 sync "$repo_root/" "s3://$bucket/" \
  --delete \
  --exclude ".DS_Store"

invalidation_id="$(
  aws cloudfront create-invalidation \
    --distribution-id "$distribution_id" \
    --paths "/*" \
    --query 'Invalidation.Id' \
    --output text
)"

printf 'PASS: published apt repository to s3://%s (invalidation %s)\n' \
  "$bucket" "$invalidation_id"
