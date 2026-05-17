# Release Signing Workflow

`release-build-sign.yml` is the canonical reusable workflow for released
artifacts. Repositories call it from release-specific workflows and pass the
artifact metadata for one artifact kind at a time.

`release-signing-dry-run.yml` is this repository's caller workflow. It builds a
test `intentproof-verify` binary, downloads that artifact into the reusable
workflow, and signs it with `attest_to_rekor: false`. It also builds and pushes
a tiny `ghcr.io/intentproof/test-hello` image, then signs and attests that
image by digest through the container path. A digest-bound `container_image_ref`
can be provided to sign an existing image instead.

`release-binaries.yml` builds the released `intentproof` and
`intentproof-verify` binaries with GoReleaser for Linux, macOS, and Windows,
uploads the archives and `SHA256SUMS` to GitHub Releases, and then calls the
reusable signing workflow for the release archives.

`release-local-image.yml` builds and pushes the multi-arch
`ghcr.io/intentproof/intentproof-local` image for Linux amd64 and arm64, then
calls the container signing workflow against the digest-bound image reference.

## Required Inputs

- `artifact_kind`: `binary`, `npm`, `pypi`, or `generic`.
- `subject_name`: the human-readable artifact name used in certificate
  subjects and provenance metadata.
- `release_version`: SemVer string for the release.
- `release_ref`: tag ref for the release, for example `refs/tags/v1.2.3`.

## Artifact Inputs

- `binary` and `generic`: set `artifact_paths` to newline-separated files.
  If files were produced by an earlier job in the same workflow run, set
  `artifact_download_name` and optionally `artifact_download_path` so the
  reusable workflow downloads them before signing.
- `container`: call `release-container-sign.yml` with `image_ref` set to a
  digest-bound GHCR reference such as
  `ghcr.io/intentproof/ingest@sha256:<digest>`.
- `npm`: set `npm_package_path`; provide `npm_token` only for real publish.
- `pypi`: set `pypi_dist_dir`. To build from source, optionally set
  `pypi_package_path` if the package is not at the repository root. To publish
  prebuilt distributions, set `artifact_download_name` and the workflow will
  download that artifact into `pypi_dist_dir` before `twine check`. PyPI
  trusted publishing is the default publish path.

The workflow fails closed when `attest_to_rekor: true` and the GitHub OIDC
token is unavailable. Non-container callers must grant:

```yaml
permissions:
  contents: write
  id-token: write
```

Container callers also need `packages: write` so the signing workflow can attach
signature and attestation artifacts to GHCR.

## Verification Shape

Binary and generic artifacts produce detached Cosign signatures, SPDX SBOMs,
SLSA provenance predicates as `.intoto.jsonl`, Sigstore bundles, and a signed
`SHA256SUMS` file.
Container artifacts are signed and SBOM-attested by digest. npm packages use
native npm provenance. PyPI packages use trusted publishing and PEP 740
attestations.

For a dry run, dispatch `release signing dry run`; it defaults to
`refs/heads/main` and sets `attest_to_rekor: false`. Leave
`container_image_ref` empty to exercise both the downloaded binary-artifact
path and the generated test-container path, or pass a digest-bound GHCR image
such as `ghcr.io/intentproof/test-hello@sha256:<digest>` to sign an existing
image. Rekor-backed releases still require a SemVer tag ref such as
`refs/tags/v1.2.3`.

Customers verify released blobs with the IntentProof GitHub Actions identity:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/IntentProof/intentproof-tools/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle intentproof-verify.sigstore.json \
  --signature intentproof-verify.sig \
  intentproof-verify
```
