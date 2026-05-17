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
    "image_ref:",
    "npm_package_path:",
    "pypi_dist_dir:",
    "pypi_package_path:",
    "attest_to_rekor:",
    "permissions:",
    "id-token: write",
    "contents: write",
    "packages: write",
    "attest_to_rekor=true requires GitHub OIDC id-token: write",
    "when attest_to_rekor=true",
    "dry-run release_ref must be a SemVer tag, refs/heads/*, or a full commit SHA",
    "cosign sign-blob",
    "--tlog-upload=false",
    "cosign attest-blob",
    "cosign sign --yes",
    "docker/login-action@v3",
    "password: ${{ github.token }}",
    '"builder":',
    '"materials":',
    "json.dumps(predicate, indent=2)",
    "python -m build --outdir",
    "ARTIFACT_DOWNLOAD_NAME",
    "syft packages",
    "npm publish --provenance",
    "PyPI trusted publishing is expected to attach PEP 740 attestations.",
]

DRY_RUN_REQUIRED_SNIPPETS = [
    "workflow_dispatch:",
    "default: refs/heads/main",
    "CGO_ENABLED=0 go build",
    "release-dry-run-binary",
    "uses: ./.github/workflows/release-build-sign.yml",
    "artifact_kind: binary",
    "artifact_download_name: release-dry-run-binary",
    "artifact_kind: container",
    "container_image_ref",
    "attest_to_rekor: false",
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

    for kind in ("binary", "container", "npm", "pypi", "generic"):
        if kind not in text:
            print(f"artifact kind {kind!r} is not represented", file=sys.stderr)
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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
