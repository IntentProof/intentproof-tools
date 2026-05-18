#!/usr/bin/env python3
"""Render Homebrew formulae from GitHub Release asset metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO = "IntentProof/intentproof-tools"
HOMEPAGE = f"https://github.com/{REPO}"

TOOLS = {
    "intentproof": {
        "class_name": "Intentproof",
        "desc": "Local loop command-line tool for signed execution proofs",
        "test": 'assert_match "Usage: intentproof <command>", shell_output("#{bin}/intentproof 2>&1", 1)',
    },
    "intentproof-verify": {
        "class_name": "IntentproofVerify",
        "desc": "IntentProof offline verifier command-line tool",
        "test": (
            'assert_match "Usage of intentproof-verify", '
            'shell_output("#{bin}/intentproof-verify --help 2>&1", 1)'
        ),
    },
}

ARCHES = {
    "arm": "arm64",
    "intel": "amd64",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--assets-json", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def load_assets(path: Path) -> dict[str, dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assets = data.get("assets", data)
    by_name: dict[str, dict[str, str]] = {}
    for asset in assets:
        name = asset["name"]
        digest = asset.get("digest") or ""
        if not digest.startswith("sha256:"):
            raise ValueError(f"asset {name} is missing a sha256 digest")
        by_name[name] = {
            "sha256": digest.removeprefix("sha256:"),
            "url": asset["url"],
        }
    return by_name


def asset(by_name: dict[str, dict[str, str]], name: str) -> dict[str, str]:
    try:
        return by_name[name]
    except KeyError as exc:
        raise ValueError(f"release asset not found: {name}") from exc


def render_resource(name: str, metadata: dict[str, str], indent: str) -> list[str]:
    return [
        f'{indent}resource "{name}" do',
        f'{indent}  url "{metadata["url"]}"',
        f'{indent}  sha256 "{metadata["sha256"]}"',
        f"{indent}end",
    ]


def render_formula(tool: str, release_tag: str, assets: dict[str, dict[str, str]]) -> str:
    version = release_tag.removeprefix("v")
    config = TOOLS[tool]
    lines = [
        "# frozen_string_literal: true",
        "",
        'require_relative "../lib/intentproof_formula_helpers"',
        "",
        f"class {config['class_name']} < Formula",
        "  include IntentproofFormulaHelpers",
        "",
        f'  desc "{config["desc"]}"',
        f'  homepage "{HOMEPAGE}"',
        f'  version "{version}"',
        '  license "Apache-2.0"',
        "",
        '  depends_on "cosign" => :build',
        "  depends_on :macos",
        "",
        "  on_macos do",
    ]

    arch_items = list(ARCHES.items())
    for index, (block_name, goarch) in enumerate(arch_items):
        archive_name = f"{tool}_{version}_darwin_{goarch}.tar.gz"
        archive = asset(assets, archive_name)
        signature = asset(assets, f"{archive_name}.sig")
        sigstore = asset(assets, f"{archive_name}.sigstore.json")
        lines.extend(
            [
                f"    on_{block_name} do",
                f'      url "{archive["url"]}"',
                f'      sha256 "{archive["sha256"]}"',
                "",
            ]
        )
        lines.extend(render_resource("signature", signature, "      "))
        lines.append("")
        lines.extend(render_resource("sigstore", sigstore, "      "))
        lines.append("    end")
        if index != len(arch_items) - 1:
            lines.append("")

    lines.extend(
        [
            "  end",
            "",
            "  def install",
            "    verify_intentproof_artifact!",
            f'    bin.install "{tool}"',
            "  end",
            "",
            "  test do",
            f"    {config['test']}",
            "  end",
            "end",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    assets = load_assets(args.assets_json)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for tool in sorted(TOOLS):
        (args.output_dir / f"{tool}.rb").write_text(
            render_formula(tool, args.release_tag, assets),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
