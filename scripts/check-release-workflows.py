#!/usr/bin/env python3
"""Lightweight structural checks for release workflow contracts."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-build-sign.yml"


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
    "attest_to_rekor:",
    "permissions:",
    "id-token: write",
    "contents: write",
    "packages: write",
    "attest_to_rekor=true requires GitHub OIDC id-token: write",
    "cosign sign-blob",
    "--tlog-upload=false",
    "cosign attest-blob",
    "cosign sign --yes",
    "syft packages",
    "npm publish --provenance",
    "PyPI trusted publishing is expected to attach PEP 740 attestations.",
]


def main() -> int:
    text = WORKFLOW.read_text()
    missing = [snippet for snippet in REQUIRED_SNIPPETS if snippet not in text]
    if missing:
        for snippet in missing:
            print(f"missing required workflow snippet: {snippet}", file=sys.stderr)
        return 1

    for kind in ("binary", "container", "npm", "pypi", "generic"):
        if kind not in text:
            print(f"artifact kind {kind!r} is not represented", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
