#!/usr/bin/env python3
"""Lightweight structural checks for release workflow contracts."""

import os
from pathlib import Path
import sys
from typing import Optional


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = Path(
    os.environ.get(
        "INTENTPROOF_RELEASE_WORKFLOW",
        ROOT / ".github" / "workflows" / "release-build-sign.yml",
    )
)
CONTAINER_WORKFLOW = Path(
    os.environ.get(
        "INTENTPROOF_RELEASE_CONTAINER_WORKFLOW",
        ROOT / ".github" / "workflows" / "release-container-sign.yml",
    )
)
RELEASE_BINARIES_WORKFLOW = Path(
    os.environ.get(
        "INTENTPROOF_RELEASE_BINARIES_WORKFLOW",
        ROOT / ".github" / "workflows" / "release-binaries.yml",
    )
)
RELEASE_LOCAL_IMAGE_WORKFLOW = Path(
    os.environ.get(
        "INTENTPROOF_RELEASE_LOCAL_IMAGE_WORKFLOW",
        ROOT / ".github" / "workflows" / "release-local-image.yml",
    )
)
GORELEASER_CONFIG = Path(
    os.environ.get("INTENTPROOF_GORELEASER_CONFIG", ROOT / ".goreleaser.yaml")
)
LOCAL_IMAGE_DOCKERFILE = Path(
    os.environ.get(
        "INTENTPROOF_LOCAL_IMAGE_DOCKERFILE",
        ROOT / "Dockerfile.intentproof-local",
    )
)
DRY_RUN_WORKFLOW = Path(
    os.environ.get(
        "INTENTPROOF_RELEASE_DRY_RUN_WORKFLOW",
        ROOT / ".github" / "workflows" / "release-signing-dry-run.yml",
    )
)


REQUIRED_SNIPPETS = [
    "workflow_call:",
    "artifact_kind:",
    "subject_name:",
    "release_version:",
    "release_ref:",
    "artifact_paths:",
    "artifact_download_name:",
    "npm_package_path:",
    "pypi_dist_dir:",
    "pypi_package_path:",
    "attest_to_rekor:",
    "permissions:",
    "id-token: write",
    "contents: read",
    "when attest_to_rekor=true",
    "dry-run release_ref must be a SemVer tag, refs/heads/*, or a full commit SHA",
    "cosign sign-blob",
    "--tlog-upload=false",
    "cosign attest-blob",
    '"builder":',
    '"materials":',
    "json.dumps(predicate, separators=(\",\", \":\"))",
    ".intoto.jsonl",
    "python -m build --outdir",
    "ARTIFACT_DOWNLOAD_NAME",
    "syft packages",
    "npm publish --provenance",
    "PyPI trusted publishing is expected to attach PEP 740 attestations.",
]

CONTAINER_REQUIRED_SNIPPETS = [
    "workflow_call:",
    "subject_name:",
    "release_version:",
    "release_ref:",
    "image_ref:",
    "registry:",
    "attest_to_rekor:",
    "packages: write",
    "id-token: write",
    "contents: read",
    "when attest_to_rekor=true",
    "image_ref must be digest-bound with @sha256:<digest>",
    "docker/login-action@v3",
    "password: ${{ github.token }}",
    "cosign sign --yes",
    "cosign attest --yes",
    "syft packages",
]

DRY_RUN_REQUIRED_SNIPPETS = [
    "workflow_dispatch:",
    "default: refs/heads/main",
    "CGO_ENABLED=0 go build",
    "release-dry-run-binary",
    "docker/build-push-action@v6",
    "ghcr.io/intentproof/test-hello:dryrun-",
    "image_ref=ghcr.io/intentproof/test-hello@",
    "uses: ./.github/workflows/release-build-sign.yml",
    "uses: ./.github/workflows/release-container-sign.yml",
    "artifact_kind: binary",
    "artifact_download_name: release-dry-run-binary",
    "container_image_ref",
    "attest_to_rekor: false",
]

RELEASE_BINARIES_REQUIRED_SNIPPETS = [
    "on:",
    "tags:",
    '"v*"',
    "goreleaser/goreleaser-action@v6",
    "SOURCE_DATE_EPOCH",
    "release-binary-artifacts",
    "uses: ./.github/workflows/release-build-sign.yml",
    "artifact_kind: binary",
    "artifact_download_path: dist",
    "attest_to_rekor: ${{ github.event_name != 'workflow_dispatch' }}",
    "release-signing-metadata",
    "GH_REPO: ${{ github.repository }}",
    "gh release upload",
]

RELEASE_LOCAL_IMAGE_REQUIRED_SNIPPETS = [
    "on:",
    "tags:",
    '"v*"',
    "docker/setup-buildx-action@v3",
    "docker/build-push-action@v6",
    "Dockerfile.intentproof-local",
    "linux/amd64,linux/arm64",
    "ghcr.io/intentproof/intentproof-local",
    'release_date="$(date -u -d "@${source_date_epoch}" +"%Y-%m-%dT%H:%M:%SZ")"',
    "DATE=${{ steps.release.outputs.release_date }}",
    "sha-",
    "uses: ./.github/workflows/release-container-sign.yml",
    "attest_to_rekor: ${{ github.event_name != 'workflow_dispatch' }}",
]

GORELEASER_REQUIRED_SNIPPETS = [
    "version: 2",
    "project_name: intentproof-tools",
    "CGO_ENABLED=0",
    "./cmd/intentproof",
    "./cmd/intentproof-verify",
    "linux",
    "darwin",
    "windows",
    "arm64",
    "amd64",
    "SHA256SUMS",
    "format_overrides:",
]

LOCAL_IMAGE_DOCKERFILE_REQUIRED_SNIPPETS = [
    "golang:1.25.0-alpine@sha256:",
    "FROM scratch",
    "SOURCE_DATE_EPOCH",
    "CGO_ENABLED=0",
    "chown -R 65532:65532 /out/home/nonroot",
    "COPY --from=build --chown=65532:65532 /out/home/nonroot /home/nonroot",
    "INTENTPROOF_LOCAL_OPEN_BROWSER=0",
    "EXPOSE 9787 9788 9789",
    'VOLUME ["/home/nonroot/.intentproof/local"]',
    'ENTRYPOINT ["/intentproof", "local"]',
]


def read_workflow(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"release workflow not found: {path}", file=sys.stderr)
        return None


def main() -> int:
    text = read_workflow(WORKFLOW)
    if text is None:
        return 1

    missing = [snippet for snippet in REQUIRED_SNIPPETS if snippet not in text]
    if missing:
        for snippet in missing:
            print(f"missing required workflow snippet: {snippet}", file=sys.stderr)
        return 1

    jobs_index = text.find("\njobs:")
    permissions_index = text.find("\npermissions:")
    if permissions_index != -1 and permissions_index < jobs_index:
        print(
            "release workflow permissions must be scoped to jobs, not workflow-wide",
            file=sys.stderr,
        )
        return 1

    if "packages: write" in text:
        print(
            "non-container release workflow must not request packages: write",
            file=sys.stderr,
        )
        return 1

    for kind in ("binary", "npm", "pypi", "generic"):
        if kind not in text:
            print(f"artifact kind {kind!r} is not represented", file=sys.stderr)
            return 1

    container_text = read_workflow(CONTAINER_WORKFLOW)
    if container_text is None:
        return 1

    container_missing = [
        snippet for snippet in CONTAINER_REQUIRED_SNIPPETS if snippet not in container_text
    ]
    if container_missing:
        for snippet in container_missing:
            print(
                f"missing required container workflow snippet: {snippet}",
                file=sys.stderr,
            )
        return 1

    dry_run_text = read_workflow(DRY_RUN_WORKFLOW)
    if dry_run_text is None:
        return 1

    dry_run_missing = [
        snippet
        for snippet in DRY_RUN_REQUIRED_SNIPPETS
        if snippet not in dry_run_text
    ]
    if dry_run_missing:
        for snippet in dry_run_missing:
            print(
                f"missing required dry-run workflow snippet: {snippet}",
                file=sys.stderr,
            )
        return 1

    for path, snippets, label in (
        (
            RELEASE_BINARIES_WORKFLOW,
            RELEASE_BINARIES_REQUIRED_SNIPPETS,
            "release binaries workflow",
        ),
        (
            RELEASE_LOCAL_IMAGE_WORKFLOW,
            RELEASE_LOCAL_IMAGE_REQUIRED_SNIPPETS,
            "release local image workflow",
        ),
        (GORELEASER_CONFIG, GORELEASER_REQUIRED_SNIPPETS, "GoReleaser config"),
        (
            LOCAL_IMAGE_DOCKERFILE,
            LOCAL_IMAGE_DOCKERFILE_REQUIRED_SNIPPETS,
            "intentproof-local Dockerfile",
        ),
    ):
        checked_text = read_workflow(path)
        if checked_text is None:
            return 1
        checked_missing = [
            snippet for snippet in snippets if snippet not in checked_text
        ]
        if checked_missing:
            for snippet in checked_missing:
                print(f"missing required {label} snippet: {snippet}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
