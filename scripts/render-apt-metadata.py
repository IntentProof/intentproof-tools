#!/usr/bin/env python3
"""Render deterministic Debian Packages and Release metadata."""

from __future__ import annotations

import argparse
import gzip
import hashlib
from pathlib import Path
import subprocess
from typing import Iterable


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def control_fields(deb: Path) -> dict[str, str]:
    output = subprocess.check_output(["dpkg-deb", "-f", str(deb)], text=True)
    fields: dict[str, str] = {}
    key = ""
    for line in output.splitlines():
        if line.startswith(" ") and key:
            fields[key] += "\n" + line
            continue
        key, _, value = line.partition(":")
        if key and value:
            fields[key] = value.strip()
    return fields


def render_packages(
    repo_root: Path, codename: str, component: str, architecture: str
) -> Path:
    package_dir = repo_root / "dists" / codename / component / f"binary-{architecture}"
    package_dir.mkdir(parents=True, exist_ok=True)
    packages_path = package_dir / "Packages"
    debs = sorted(repo_root.glob(f"pool/**/*.deb"))
    stanzas: list[str] = []
    for deb in debs:
        fields = control_fields(deb)
        if fields.get("Architecture") != architecture:
            continue
        relative = deb.relative_to(repo_root).as_posix()
        ordered_keys = [
            "Package",
            "Version",
            "Architecture",
            "Maintainer",
            "Installed-Size",
            "Section",
            "Priority",
            "Homepage",
            "Description",
        ]
        lines = [f"{key}: {fields[key]}" for key in ordered_keys if key in fields]
        lines.extend(
            [
                f"Filename: {relative}",
                f"Size: {deb.stat().st_size}",
                f"SHA256: {sha256(deb)}",
            ]
        )
        stanzas.append("\n".join(lines))
    packages_path.write_text("\n\n".join(stanzas) + "\n", encoding="utf-8")
    with gzip.GzipFile(filename="", mode="wb", fileobj=(package_dir / "Packages.gz").open("wb"), mtime=0) as gz:
        gz.write(packages_path.read_bytes())
    return packages_path


def release_checksums(repo_root: Path, codename: str, paths: Iterable[Path]) -> list[str]:
    rows = []
    for path in sorted(paths):
        rel = path.relative_to(repo_root / "dists" / codename).as_posix()
        rows.append(f" {sha256(path)} {path.stat().st_size:16d} {rel}")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--codename", required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--architectures", nargs="+", required=True)
    args = parser.parse_args()

    repo_root = args.repo_root
    metadata_paths = []
    for arch in args.architectures:
        packages = render_packages(repo_root, args.codename, args.component, arch)
        metadata_paths.append(packages)
        metadata_paths.append(packages.with_suffix(packages.suffix + ".gz"))

    release_path = repo_root / "dists" / args.codename / "Release"
    release_path.parent.mkdir(parents=True, exist_ok=True)
    release = [
        "Origin: IntentProof",
        "Label: IntentProof",
        f"Suite: {args.suite}",
        f"Codename: {args.codename}",
        f"Architectures: {' '.join(args.architectures)}",
        f"Components: {args.component}",
        "Description: IntentProof Debian package repository",
        "SHA256:",
        *release_checksums(repo_root, args.codename, metadata_paths),
        "",
    ]
    release_path.write_text("\n".join(release), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
