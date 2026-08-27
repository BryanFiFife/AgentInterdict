#!/usr/bin/env python3
"""Build self-contained AgentInterdict release packages with integrity manifests.

All tiers ship the same hardened local runtime and immutable Community baseline.
A signed paid licence selects eligible remote features at runtime; paid threat
feeds are authenticated, signature-verified, and only add to the local baseline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agentinterdict.version import VERSION

DEFAULT_OUT = ROOT / "dist_packages"
TIERS = {"community", "pro", "business", "enterprise"}


def _should_include(rel: str) -> bool:
    parts = rel.split("/")
    if any(part in {".git", ".venv", "__pycache__", ".pytest_cache", "backups", "data", "secrets", "dist_packages"} for part in parts):
        return False
    if rel.endswith((".pyc", ".db", ".db-wal", ".db-shm", ".log", ".pid")):
        return False
    if rel in {".env", ".agentinterdict-secret", ".agentinterdict-operator-key", ".agentinterdict-port", "installation-result.json", "commercial.db", "RELEASE_MANIFEST.json"}:
        return False
    if rel.endswith(".pem") and rel != "agentinterdict/license_public_key.pem":
        return False
    return True


def _collect_files(exclude_roots: list[Path] | None = None) -> list[tuple[str, Path]]:
    """Collect release source files while excluding the active build output tree.

    This must be path-based rather than name-based: callers are allowed to build
    into ROOT/dist, ROOT/releases, or any other directory without recursively
    packaging artifacts produced earlier in the same run.
    """
    excluded = [p.expanduser().resolve() for p in (exclude_roots or [])]

    def excluded_path(path: Path) -> bool:
        resolved = path.resolve()
        for root in excluded:
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    out = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_file() and not excluded_path(path):
            rel = path.relative_to(ROOT).as_posix()
            if _should_include(rel):
                out.append((rel, path))
    return out


def _package_readme(tier: str) -> str:
    if tier == "community":
        plan = "Community runs fully offline with the baked-in threat baseline and requires no activation."
    else:
        plan = (
            f"{tier.title()} uses the same hardened local runtime. Activate a signed {tier.title()} lease with "
            "scripts/activate.py, then restart AgentInterdict. The runtime derives the plan from the signed lease, "
            "authenticates the control-plane request, verifies the Ed25519-signed threat bundle, and always keeps "
            "the Community rules as a non-removable baseline. If the remote service is unavailable or invalid, "
            "enforcement safely falls back to the local baseline."
        )
    return f"""AgentInterdict {VERSION} - {tier.title()} package

{plan}

Install:
  python scripts/self_install.py --with-mcp

Windows:
  run_windows.bat

Verify this extracted package before installation:
  python scripts/verify_release.py

Dashboard default:
  http://127.0.0.1:43847
"""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_manifest(tmp: Path, tier: str) -> None:
    files = {}
    for path in sorted(tmp.rglob("*")):
        if path.is_file() and path.name != "RELEASE_MANIFEST.json":
            files[path.relative_to(tmp).as_posix()] = _sha256(path)
    manifest = {
        "product": "AgentInterdict", "version": VERSION, "tier": tier,
        "generated_at": datetime.now(timezone.utc).isoformat(), "algorithm": "sha256", "files": files,
    }
    (tmp / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_package(tier: str, out_dir: Path) -> Path:
    if tier not in TIERS:
        raise ValueError(f"unknown tier: {tier}")
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / f"agentinterdict-{tier}-tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True, exist_ok=True)
    source_files = _collect_files([out_dir])
    for rel, src in source_files:
        dest = tmp / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    (tmp / "PACKAGE_README.txt").write_text(_package_readme(tier), encoding="utf-8")
    _write_manifest(tmp, tier)
    zip_path = out_dir / f"agentinterdict-{tier}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(tmp.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(tmp).as_posix())
    shutil.rmtree(tmp)
    return zip_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Build AgentInterdict release packages")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--tier", default="community,pro,business,enterprise", help="Comma-separated tiers to build")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    tiers = [x.strip() for x in args.tier.split(",") if x.strip()]
    for tier in tiers:
        zip_path = build_package(tier, args.out)
        print(f"Built {tier}: {zip_path} ({zip_path.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        raise SystemExit(2)
