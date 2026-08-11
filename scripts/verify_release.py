#!/usr/bin/env python3
"""Verify shipped-file SHA-256 hashes from RELEASE_MANIFEST.json.

The manifest detects accidental/local modification of files covered by the package. It is
not a publisher-authenticity signature; production releases should additionally sign the
release/checksum with an offline vendor release key.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "RELEASE_MANIFEST.json"
MAX_MANIFEST = 4_000_000


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if not MANIFEST.is_file() or MANIFEST.stat().st_size > MAX_MANIFEST:
        print("FAIL: RELEASE_MANIFEST.json is missing or unexpectedly large")
        return 2
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"FAIL: invalid release manifest: {exc}")
        return 2
    files = data.get("files")
    if not isinstance(files, dict) or not files:
        print("FAIL: release manifest contains no file hashes")
        return 2
    problems = []
    for rel, expected in sorted(files.items()):
        if not isinstance(rel, str) or not isinstance(expected, str) or len(expected) != 64:
            problems.append(f"invalid manifest entry: {rel!r}")
            continue
        path = (ROOT / rel).resolve()
        try:
            path.relative_to(ROOT.resolve())
        except ValueError:
            problems.append(f"path escapes release root: {rel}")
            continue
        if not path.is_file():
            problems.append(f"missing: {rel}")
            continue
        actual = sha256(path)
        if actual != expected:
            problems.append(f"hash mismatch: {rel}")
    if problems:
        for problem in problems:
            print("FAIL:", problem)
        return 2
    print(f"OK: verified {len(files)} shipped files for MemoryGuard {data.get('version', 'unknown')}")
    print("NOTE: this SHA-256 manifest detects modification but is not a vendor authenticity signature.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
