#!/usr/bin/env python3
"""Verify the SHA-256 release manifest embedded in an extracted package."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agentinterdict.version import VERSION

MANIFEST = ROOT / "RELEASE_MANIFEST.json"
MAX_MANIFEST = 4_000_000


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
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
    if data.get("product") != "AgentInterdict" or data.get("algorithm") != "sha256":
        print("FAIL: release manifest identity/algorithm is invalid")
        return 2
    if data.get("version") != VERSION:
        print(f"FAIL: manifest version {data.get('version')!r} does not match runtime {VERSION!r}")
        return 2
    if data.get("tier") not in {"community", "pro", "business", "enterprise"}:
        print("FAIL: release manifest tier is invalid")
        return 2
    if not isinstance(files, dict) or not files:
        print("FAIL: release manifest contains no file hashes")
        return 2
    required = {"agentinterdict/version.py", "agentinterdict/threats/community.json", "scripts/verify_release.py", "PACKAGE_README.txt"}
    problems = []
    if not required.issubset(files):
        problems.append("manifest is missing one or more required release files")
    root_resolved = ROOT.resolve()
    for rel, expected in sorted(files.items()):
        if not isinstance(rel, str) or not isinstance(expected, str) or len(expected) != 64:
            problems.append(f"invalid manifest entry: {rel!r}")
            continue
        path = (ROOT / rel).resolve()
        try:
            path.relative_to(root_resolved)
        except ValueError:
            problems.append(f"path escapes release root: {rel}")
            continue
        if not path.is_file():
            problems.append(f"missing: {rel}")
            continue
        if sha256(path) != expected:
            problems.append(f"hash mismatch: {rel}")
    if problems:
        for problem in problems:
            print("FAIL:", problem)
        return 2
    print(f"OK: verified {len(files)} shipped files for AgentInterdict {VERSION} ({data['tier']})")
    print("NOTE: SHA-256 detects modification; GitHub release provenance/attestation authenticates publisher build origin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
