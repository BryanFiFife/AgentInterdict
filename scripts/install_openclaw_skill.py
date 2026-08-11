from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "agent_install" / "openclaw-skill" / "memoryguard" / "SKILL.md"


def _runtime_python() -> Path:
    candidate = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if candidate.is_file():
        return candidate
    result_file = ROOT / "installation-result.json"
    if result_file.is_file() and result_file.stat().st_size < 256_000:
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
            raw = data.get("runtime_python")
            if isinstance(raw, str) and raw.strip():
                candidate = Path(raw).expanduser().resolve()
                if candidate.is_file():
                    return candidate
        except (OSError, json.JSONDecodeError, ValueError, TypeError):
            pass
    raise SystemExit("MemoryGuard runtime Python is missing; run scripts/self_install.py first")


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent, text=True)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Install the MemoryGuard skill into an OpenClaw workspace")
    ap.add_argument("--workspace", required=True, help="Absolute OpenClaw workspace directory")
    args = ap.parse_args()
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists() or not workspace.is_dir():
        raise SystemExit(f"workspace does not exist: {workspace}")
    if not TEMPLATE.is_file():
        raise SystemExit(f"MemoryGuard OpenClaw skill template is missing: {TEMPLATE}")

    target = workspace / "skills" / "memoryguard"
    target.mkdir(parents=True, exist_ok=True)
    target_file = target / "SKILL.md"
    if target_file.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = target / f"SKILL.md.pre-memoryguard-{stamp}.bak"
        shutil.copy2(target_file, backup)
        print(f"Backed up existing skill to {backup}")

    runtime = _runtime_python()
    text = TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("__MEMORYGUARD_ROOT__", str(ROOT)).replace("__VENV_PYTHON__", str(runtime))
    if "__MEMORYGUARD_ROOT__" in text or "__VENV_PYTHON__" in text:
        raise SystemExit("OpenClaw skill template rendering failed; placeholders remain")
    _atomic_write(target_file, text)
    print(target_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
