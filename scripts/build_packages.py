#!/usr/bin/env python3
"""Build per-tier AgentInterdict download packages.

Assembles a self-contained ZIP for each tier:
  - community: static baked-in threat list (community.json), no network needed
  - pro / business / enterprise: dynamic threat list fetched from the vendor
    control plane (/v1/threats?tier=...), refreshed weekly by the Worker cron

Each package contains the full AgentInterdict source, the tier's threat list,
the activation client, the licence public key, and install docs.

Usage:
  python scripts/build_packages.py [--out DIR] [--tier community,pro,business,enterprise]
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "dist_packages"

# Files/dirs to exclude from every package (secrets, caches, dev artifacts).
EXCLUDE = {
    ".git", ".venv", "__pycache__", ".pytest_cache", "*.pyc", "*.db", "*.db-wal",
    "*.db-shm", ".env", ".agentinterdict-secret", ".agentinterdict-operator-key",
    ".agentinterdict-port", "installation-result.json", "backups", "data", "secrets",
    "commercial.db", "dist_packages", "*.pem", "!agentinterdict/license_public_key.pem",
}

# Threat-list source per tier.
# community -> static baked-in file. paid -> fetched from the Worker.
THREAT_SOURCE = {
    "community": "static",
    "pro": "remote",
    "business": "remote",
    "enterprise": "remote",
}

# Default control-plane base URL for paid tiers (overridable).
DEFAULT_CONTROL_PLANE = "https://agentinterdict-funnel.bryansmall26.workers.dev"


def _should_include(rel: str) -> bool:
    parts = rel.split("/")
    for part in parts:
        if part in {".git", ".venv", "__pycache__", ".pytest_cache", "backups", "data", "secrets", "dist_packages"}:
            return False
    if rel.endswith((".pyc", ".db", ".db-wal", ".db-shm", ".log", ".pid")):
        return False
    if rel in {".env", ".agentinterdict-secret", ".agentinterdict-operator-key", ".agentinterdict-port", "installation-result.json", "commercial.db"}:
        return False
    if rel.endswith(".pem") and rel != "agentinterdict/license_public_key.pem":
        return False
    return True


def _collect_files() -> list[tuple[str, Path]]:
    out = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if _should_include(rel):
            out.append((rel, path))
    return out


def _write_threat_list(tier: str, tmp: Path) -> None:
    """Write the tier's threat list into the package's agentinterdict/threats/ dir."""
    dest_dir = tmp / "agentinterdict" / "threats"
    dest_dir.mkdir(parents=True, exist_ok=True)
    if THREAT_SOURCE[tier] == "static":
        # Copy the baked-in community list.
        src = ROOT / "agentinterdict" / "threats" / "community.json"
        shutil.copy2(src, dest_dir / "community.json")
    else:
        # Paid tier: write a small JSON that tells the runtime to fetch the
        # current list from the control plane (updated weekly by the Worker cron).
        remote = {
            "version": 0,
            "updated_at": "",
            "tier": tier,
            "remote_url": f"{DEFAULT_CONTROL_PLANE}/v1/threats?tier={tier}",
            "refresh": "weekly",
        }
        (dest_dir / f"{tier}.json").write_text(json.dumps(remote, indent=2), encoding="utf-8")


def _write_install_doc(tier: str, tmp: Path) -> None:
    """Write a tier-specific install/activation README into the package."""
    if THREAT_SOURCE[tier] == "static":
        threat_note = (
            "This Community build ships a static, baked-in threat list. "
            "It does not require a network connection to scan."
        )
        activate_note = "Community is free and needs no activation key."
    else:
        threat_note = (
            f"This {tier.title()} build fetches an updated threat list from the "
            f"AgentInterdict control plane ({DEFAULT_CONTROL_PLANE}/v1/threats?tier={tier}). "
            "The list is refreshed weekly. An internet connection is required to "
            "receive threat updates."
        )
        activate_note = (
            f"To activate your {tier.title()} licence, run:\n"
            f"  python scripts/activate.py --server {DEFAULT_CONTROL_PLANE} --license-key <YOUR_KEY>"
        )
    doc = f"""# AgentInterdict {tier.title()} package

## What's included
- Full AgentInterdict source (agentinterdict/)
- {tier.title()} threat list
- Activation client (scripts/activate.py)
- Licence public key (agentinterdict/license_public_key.pem)
- Install docs

## Threat list
{threat_note}

## Activation
{activate_note}

## Install
Run:
  python scripts/self_install.py --with-mcp

Then open the dashboard at http://127.0.0.1:43847
"""
    (tmp / "PACKAGE_README.txt").write_text(doc, encoding="utf-8")


def build_package(tier: str, out_dir: Path) -> Path:
    tmp = out_dir / f"agentinterdict-{tier}-tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True, exist_ok=True)

    # Copy all included files.
    for rel, src in _collect_files():
        dest = tmp / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)

    # Overlay tier-specific threat list + install doc.
    _write_threat_list(tier, tmp)
    _write_install_doc(tier, tmp)

    # Zip it. Collect the full file list once, then add tier-specific files.
    zip_path = out_dir / f"agentinterdict-{tier}.zip"
    added: set[str] = set()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, _ in _collect_files():
            p = tmp / rel
            if p.is_file() and rel not in added:
                zf.write(p, rel)
                added.add(rel)
        # Add the tier-specific threat list + install doc (skip if already added).
        for extra in (tmp / "agentinterdict" / "threats").rglob("*"):
            if extra.is_file():
                rel = extra.relative_to(tmp).as_posix()
                if rel not in added:
                    zf.write(extra, rel)
                    added.add(rel)
        pkg_readme = tmp / "PACKAGE_README.txt"
        if pkg_readme.is_file() and "PACKAGE_README.txt" not in added:
            zf.write(pkg_readme, "PACKAGE_README.txt")

    shutil.rmtree(tmp)
    return zip_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Build AgentInterdict tier packages")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--tier", default="community,pro,business,enterprise",
                    help="Comma-separated tiers to build")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    tiers = [t.strip() for t in args.tier.split(",") if t.strip()]
    for tier in tiers:
        if tier not in THREAT_SOURCE:
            print(f"SKIP unknown tier: {tier}")
            continue
        zip_path = build_package(tier, args.out)
        size_kb = zip_path.stat().st_size / 1024
        print(f"Built {tier}: {zip_path} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"BUILD FAILED: {exc}", file=sys.stderr)
        raise SystemExit(2)
