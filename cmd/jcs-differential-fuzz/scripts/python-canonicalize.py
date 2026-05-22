#!/usr/bin/env python3
"""Read one JSON value from stdin, strip signature, emit JCS canonical UTF-8."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

if len(sys.argv) != 2:
    sys.stderr.write("usage: python-canonicalize.py <sdk-src-root>\n")
    sys.exit(2)

src_root = Path(sys.argv[1]).resolve()
canon_path = src_root / "intentproof" / "canon.py"
if not canon_path.is_file():
    sys.stderr.write(f"canon module not found: {canon_path}\n")
    sys.exit(2)

spec = importlib.util.spec_from_file_location("intentproof_canon", canon_path)
if spec is None or spec.loader is None:
    sys.stderr.write(f"failed to load canon module: {canon_path}\n")
    sys.exit(2)
canon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canon)

raw = sys.stdin.read()
value = json.loads(raw)
unsigned = {k: v for k, v in value.items() if k != "signature"}
sys.stdout.write(canon.canonicalize(unsigned))
