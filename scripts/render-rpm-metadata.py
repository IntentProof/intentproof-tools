#!/usr/bin/env python3
"""Generate createrepo_c metadata for RPM repository paths."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--repo-path", nargs="+", required=True)
    args = parser.parse_args()

    createrepo = shutil.which("createrepo_c") or shutil.which("createrepo")
    if createrepo is None:
        print(
            "createrepo_c is required to render RPM repository metadata.",
            file=sys.stderr,
        )
        return 1

    repo_root = args.repo_root
    for repo_path in args.repo_path:
        target = repo_root / repo_path
        if not target.is_dir():
            print(f"missing RPM repository path: {target}", file=sys.stderr)
            return 1
        rpms = sorted(target.glob("*.rpm"))
        if not rpms:
            print(f"no RPM packages found in {target}", file=sys.stderr)
            return 1
        subprocess.run(
            [createrepo, "--no-database", str(target)],
            check=True,
        )
        repomd = target / "repodata" / "repomd.xml"
        if not repomd.is_file():
            print(f"missing repomd.xml for {target}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
