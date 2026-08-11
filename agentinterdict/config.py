from __future__ import annotations

import os
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent

VERSION = "0.4.0"
DEFAULT_PORT = 43847
DEFAULT_DB = PROJECT_ROOT / "agentinterdict.db"
DEFAULT_BACKUP_DIR = PROJECT_ROOT / "backups"
DEFAULT_MAX_CONTENT = 100_000
DEFAULT_MAX_METADATA_BYTES = 65_536
DEFAULT_MAX_PARENTS = 64


def env_int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def port() -> int:
    raw = os.getenv("AGENTINTERDICT_PORT")
    if raw in (None, ""):
        return DEFAULT_PORT
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("AGENTINTERDICT_PORT must be an integer") from exc
    if not 1024 <= value <= 65535:
        raise ValueError("AGENTINTERDICT_PORT must be between 1024 and 65535")
    return value


def db_path() -> Path:
    return Path(os.getenv("AGENTINTERDICT_DB", str(DEFAULT_DB))).expanduser().resolve()


def backup_dir() -> Path:
    return Path(os.getenv("AGENTINTERDICT_BACKUP_DIR", str(DEFAULT_BACKUP_DIR))).expanduser().resolve()


def api_key() -> str:
    return os.getenv("AGENTINTERDICT_API_KEY", "").strip()



def operator_key() -> str:
    return os.getenv("AGENTINTERDICT_OPERATOR_KEY", "").strip()


def bind_host() -> str:
    return os.getenv("AGENTINTERDICT_HOST", "127.0.0.1").strip() or "127.0.0.1"


def is_remote_bind() -> bool:
    return bind_host() not in {"127.0.0.1", "localhost", "::1"}
