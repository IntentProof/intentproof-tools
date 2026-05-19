#!/usr/bin/env bash
# Simulates package-signing key rotation using ephemeral local GPG keys.
# Production rotation uses a second KMS key per docs/pkg-repo-signing.md.
set -euo pipefail

if ! command -v gpg >/dev/null 2>&1; then
  printf 'gpg is required\n' >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
export GNUPGHOME="${workdir}/gnupg"
mkdir -m 0700 "${GNUPGHOME}"

gen_key() {
  local label="$1"
  local email="$2"
  local batch="${workdir}/gen-${label}.batch"
  cat >"${batch}" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Name-Real: IntentProof Package Repository (${label})
Name-Email: ${email}
Expire-Date: 0
%commit
EOF
  gpg --batch --generate-key "${batch}"
}

key_fingerprint() {
  local email="$1"
  gpg --with-colons --fingerprint "${email}" | awk -F: '$1=="fpr" {print $10; exit}'
}

gen_key OLD old-rotation-dryrun@intentproof.io
old_fp="$(key_fingerprint old-rotation-dryrun@intentproof.io)"
gen_key NEW new-rotation-dryrun@intentproof.io
new_fp="$(key_fingerprint new-rotation-dryrun@intentproof.io)"

if [[ -z "${old_fp}" || -z "${new_fp}" ]]; then
  printf 'failed to read dry-run key fingerprints\n' >&2
  exit 1
fi

effective="2026-06-01"
overlap_end="2026-09-01"
statement="${workdir}/key-transition-statement.txt"
cat >"${statement}" <<EOF
IntentProof package repository signing key transition (dry run)

Old fingerprint: ${old_fp}
New fingerprint: ${new_fp}
Effective date: ${effective}
Overlap end date: ${overlap_end}
Reason: scheduled rotation dry run (no production key change)
EOF

gpg --batch --yes --local-user "${old_fp}" --armor --detach-sign \
  --output "${workdir}/key-transition-statement.txt.old.asc" "${statement}"
gpg --batch --yes --local-user "${new_fp}" --armor --detach-sign \
  --output "${workdir}/key-transition-statement.txt.new.asc" "${statement}"

gpg --verify "${workdir}/key-transition-statement.txt.old.asc" "${statement}"
gpg --verify "${workdir}/key-transition-statement.txt.new.asc" "${statement}"

release="${workdir}/Release"
printf 'Origin: IntentProof\nLabel: IntentProof\nSuite: stable\nCodename: stable\n' >"${release}"
gpg --batch --yes --local-user "${new_fp}" --armor --detach-sign \
  --output "${workdir}/Release.gpg" "${release}"

combined="${workdir}/combined.gpg"
gpg --export "${old_fp}" "${new_fp}" >"${combined}"
gpg --no-default-keyring --keyring "${combined}" --verify "${workdir}/Release.gpg" "${release}"

printf 'PASS: rotation dry run\n'
printf '  old fingerprint: %s\n' "${old_fp}"
printf '  new fingerprint: %s\n' "${new_fp}"
printf '  transition statement verifies under both keys\n'
printf '  sample Release signed by new key verifies with dual keyring\n'
