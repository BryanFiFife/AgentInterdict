"""Threat-list loader for AgentInterdict.

Loads the active threat list (SIGNALS + COMPACT_PATTERNS) from a JSON data file
so the list can be versioned and updated independently of the code. The Community
build ships a static baked-in list; paid tiers fetch a newer list from the vendor
control plane (see the Worker's /v1/threats endpoint).

The JSON schema is:
{
  "version": int,
  "updated_at": ISO-8601,
  "tier": "community" | "pro" | "business" | "enterprise",
  "signals": [ { "name", "pattern", "flags", "weight", "reason" }, ... ],
  "compact_patterns": [ { "name", "pattern", "flags", "weight", "reason" }, ... ]
}
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_THREAT_FILE = PACKAGE_ROOT / "threats" / "community.json"

# Regex flag mapping (subset used by the threat list).
_FLAG_MAP = {
    "i": re.IGNORECASE,
    "s": re.DOTALL,
    "m": re.MULTILINE,
    "x": re.VERBOSE,
}


def _compile_flags(flags: str) -> int:
    out = 0
    for ch in flags or "":
        out |= _FLAG_MAP.get(ch, 0)
    return out


def _load_threat_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"threat list not found: {path}")
    if path.stat().st_size > 4_000_000:
        raise ValueError("threat list is unexpectedly large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("threat list has an invalid schema")
    # A remote-ref stub (paid tier) has no inline signals; it points at the
    # control plane. Allow it so load_threats can fetch the current list.
    if data.get("remote_url"):
        return data
    if not isinstance(data.get("signals"), list):
        raise ValueError("threat list has an invalid schema")
    return data


def load_threats(path: Path | None = None) -> dict[str, Any]:
    """Load and compile the threat list from a JSON file.

    Returns a dict with 'version', 'updated_at', 'tier', 'signals' (list of
    (name, compiled_pattern, weight, reason)) and 'compact_patterns' (same shape).
    """
    file = Path(path) if path is not None else Path(
        os.getenv("AGENTINTERDICT_THREAT_FILE", str(DEFAULT_THREAT_FILE))
    ).expanduser()
    data = _load_threat_file(file)

    # If the file is a remote-ref stub (paid tier), fetch the current list.
    if data.get("remote_url"):
        data = _fetch_remote_threats(data["remote_url"]) or data

    def compile_list(items: list[Any]) -> list[tuple[str, re.Pattern[str], int, str]]:
        out = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            pattern = str(item.get("pattern", ""))
            flags = str(item.get("flags", ""))
            weight = int(item.get("weight", 0))
            reason = str(item.get("reason", ""))
            if not name or not pattern:
                continue
            try:
                compiled = re.compile(pattern, _compile_flags(flags))
            except re.error:
                continue
            out.append((name, compiled, weight, reason))
        return out

    return {
        "version": int(data.get("version", 1)),
        "updated_at": str(data.get("updated_at", "")),
        "tier": str(data.get("tier", "community")),
        "signals": compile_list(data.get("signals", [])),
        "compact_patterns": compile_list(data.get("compact_patterns", [])),
    }


def _fetch_remote_threats(url: str) -> dict[str, Any] | None:
    """Fetch the current threat list from the vendor control plane.

    Uses stdlib urllib so the runtime needs no extra dependency. Fails soft:
    if the control plane is unreachable, returns None so the caller falls back
    to the last-known local list.
    """
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            if resp.status != 200:
                return None
            raw = resp.read(4_000_000)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("signals"), list):
            return None
        return data
    except Exception:
        return None


# Load the active threat list once at import time. The Community build uses the
# static baked-in list; a paid build can point AGENTINTERDICT_THREAT_FILE at a
# downloaded newer list.
ACTIVE_THREATS = load_threats()
SIGNALS: list[tuple[str, re.Pattern[str], int, str]] = ACTIVE_THREATS["signals"]
COMPACT_PATTERNS: list[tuple[str, re.Pattern[str], int, str]] = ACTIVE_THREATS["compact_patterns"]
THREAT_VERSION: int = ACTIVE_THREATS["version"]
THREAT_UPDATED_AT: str = ACTIVE_THREATS["updated_at"]
