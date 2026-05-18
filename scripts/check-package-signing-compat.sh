#!/usr/bin/env bash
set -euo pipefail

missing=()
for tool in gpg apt-key rpm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  printf 'missing required package signing compatibility tool(s): %s\n' "${missing[*]}" >&2
  printf 'run this check on Linux with gnupg, apt, and rpm installed.\n' >&2
  exit 1
fi

go test ./pkg/openpgpkms -run 'TestArmoredDetachSignVerifiesWith(GPG|AptKey)WhenAvailable' -count=1

# The current helper emits OpenPGP detached signatures for repository metadata.
# Embedded RPM package signatures are produced by the later RPM publishing
# pipeline; keep this explicit so rpm --checksig coverage is not mistaken for
# repository metadata signature coverage.
rpm --version >/dev/null
printf 'PASS: apt/gpg package metadata compatibility checks passed; rpm tooling is present for the later RPM package-signature harness.\n'
