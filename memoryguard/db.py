from __future__ import annotations

import json
import os
import sqlite3
import threading
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .errors import StorageBusyError, StorageCorruptionError, StorageError
from .security import sign_record, verify_signature

DB_PATH = config.db_path()
_LOCK = threading.RLock()
SCHEMA_VERSION = 5

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  namespace TEXT NOT NULL DEFAULT 'default',
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_uri TEXT,
  origin_id TEXT NOT NULL,
  origin_roots TEXT NOT NULL DEFAULT '[]',
  parent_ids TEXT NOT NULL DEFAULT '[]',
  authority TEXT NOT NULL,
  status TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  risk_severity TEXT NOT NULL,
  risk_signals TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  signature TEXT NOT NULL,
  state_signature TEXT NOT NULL DEFAULT '',
  revision INTEGER NOT NULL DEFAULT 1,
  supersedes_id INTEGER,
  idempotency_key TEXT,
  request_fingerprint TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(supersedes_id) REFERENCES memories(id)
);
CREATE INDEX IF NOT EXISTS idx_memories_ns_status ON memories(namespace,status);
CREATE INDEX IF NOT EXISTS idx_memories_origin ON memories(origin_id);
CREATE INDEX IF NOT EXISTS idx_memories_created ON memories(created_at);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  memory_id INTEGER,
  actor TEXT NOT NULL,
  payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  event_signature TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(memory_id) REFERENCES memories(id)
);
CREATE INDEX IF NOT EXISTS idx_audit_memory ON audit_events(memory_id);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _execute_schema_statements(con: sqlite3.Connection) -> None:
    """Execute the simple static schema without executescript's implicit transaction behavior."""
    for statement in BASE_SCHEMA.split(";"):
        statement = statement.strip()
        if statement:
            con.execute(statement)


def _connect_raw() -> sqlite3.Connection:
    global DB_PATH
    # Retain mutable DB_PATH for the test suite while making env-based runtime setup robust.
    timeout = max(1, config.env_int("MEMORYGUARD_SQLITE_TIMEOUT", 10, 1, 60))
    con = sqlite3.connect(DB_PATH, timeout=timeout, isolation_level=None, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute(f"PRAGMA busy_timeout={timeout * 1000}")
    con.execute("PRAGMA synchronous=FULL")
    try:
        con.execute("PRAGMA trusted_schema=OFF")
    except sqlite3.DatabaseError:
        pass
    return con


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}


def _ensure_column(con: sqlite3.Connection, table: str, name: str, declaration: str) -> None:
    if name not in _columns(con, table):
        con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def _schema_version(con: sqlite3.Connection) -> int:
    try:
        row = con.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        return int(row[0]) if row else 0
    except (sqlite3.DatabaseError, ValueError):
        return 0


def _ensure_secret_binding(con: sqlite3.Connection) -> None:
    """Bind this database instance to the configured local HMAC secret.

    This catches accidental secret rotation at startup before signed memory silently
    becomes unavailable. It is not a substitute for protecting the secret from a
    same-host privileged attacker.
    """
    instance = con.execute("SELECT value FROM schema_meta WHERE key='instance_id'").fetchone()
    instance_id = str(instance[0]) if instance and instance[0] else ""
    if not instance_id:
        instance_id = secrets.token_hex(16)
        con.execute("INSERT INTO schema_meta(key,value) VALUES('instance_id',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (instance_id,))
    payload = {"purpose": "memoryguard-db-secret-check-v1", "instance_id": instance_id}
    check = con.execute("SELECT value FROM schema_meta WHERE key='secret_check'").fetchone()
    if check and check[0]:
        if not verify_signature(payload, str(check[0])):
            raise StorageError("MemoryGuard signing secret does not match this database; restore the original .memoryguard-secret/environment value before continuing")
    else:
        con.execute("INSERT INTO schema_meta(key,value) VALUES('secret_check',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (sign_record(payload),))



def _secret_binding_valid(con: sqlite3.Connection) -> bool:
    instance = con.execute("SELECT value FROM schema_meta WHERE key='instance_id'").fetchone()
    check = con.execute("SELECT value FROM schema_meta WHERE key='secret_check'").fetchone()
    if not instance or not instance[0] or not check or not check[0]:
        return False
    payload = {"purpose": "memoryguard-db-secret-check-v1", "instance_id": str(instance[0])}
    return verify_signature(payload, str(check[0]))

RUNTIME_MODES = {"normal", "read_only", "lockdown"}

def _runtime_mode_payload(mode: str) -> dict:
    return {"purpose": "memoryguard-runtime-mode-v1", "mode": mode}

def _ensure_runtime_mode(con: sqlite3.Connection) -> None:
    row = con.execute("SELECT value FROM schema_meta WHERE key='runtime_mode'").fetchone()
    sig = con.execute("SELECT value FROM schema_meta WHERE key='runtime_mode_signature'").fetchone()
    if row and row[0] and sig and sig[0]:
        return
    mode = "normal"
    signature = sign_record(_runtime_mode_payload(mode))
    con.execute("INSERT INTO schema_meta(key,value) VALUES('runtime_mode',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (mode,))
    con.execute("INSERT INTO schema_meta(key,value) VALUES('runtime_mode_signature',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (signature,))

def runtime_mode_status(con: sqlite3.Connection | None = None) -> dict:
    own = con is None
    if own:
        con = _connect_raw()
    try:
        row = con.execute("SELECT value FROM schema_meta WHERE key='runtime_mode'").fetchone()
        sig = con.execute("SELECT value FROM schema_meta WHERE key='runtime_mode_signature'").fetchone()
        mode = str(row[0]) if row and row[0] else "lockdown"
        signature = str(sig[0]) if sig and sig[0] else ""
        valid = mode in RUNTIME_MODES and bool(signature) and verify_signature(_runtime_mode_payload(mode), signature)
        return {"mode": mode if valid else "lockdown", "valid": valid}
    finally:
        if own and con is not None:
            con.close()

def set_runtime_mode(mode: str, con: sqlite3.Connection | None = None) -> dict:
    if mode not in RUNTIME_MODES:
        raise ValueError("invalid runtime mode")
    def _apply(target: sqlite3.Connection) -> dict:
        signature = sign_record(_runtime_mode_payload(mode))
        target.execute("INSERT INTO schema_meta(key,value) VALUES('runtime_mode',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (mode,))
        target.execute("INSERT INTO schema_meta(key,value) VALUES('runtime_mode_signature',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (signature,))
        return {"mode": mode, "valid": True}
    if con is not None:
        return _apply(con)
    with connect(write=True) as own_con:
        return _apply(own_con)

def _backup_before_migration() -> Path | None:
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        return None
    dest_dir = config.backup_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = dest_dir / f"memoryguard-pre-migration-{stamp}.db"
    source = target = verify = None
    try:
        source = sqlite3.connect(DB_PATH, timeout=5)
        target = sqlite3.connect(dest, timeout=5)
        with target:
            source.backup(target)
        target.close(); target = None
        source.close(); source = None
        verify = sqlite3.connect(dest, timeout=5)
        quick = verify.execute("PRAGMA quick_check").fetchone()[0]
        if quick != "ok":
            raise sqlite3.DatabaseError(f"pre-migration backup quick_check failed: {quick}")
        return dest
    except sqlite3.DatabaseError as exc:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        raise StorageError(f"Unable to create a verified pre-migration backup: {exc}") from exc
    finally:
        for con in (verify, target, source):
            if con is not None:
                try:
                    con.close()
                except sqlite3.Error:
                    pass


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    needs_backup = False
    if DB_PATH.exists() and DB_PATH.stat().st_size:
        try:
            probe = _connect_raw()
            has_meta = probe.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta'").fetchone() is not None
            needs_backup = (not has_meta) or _schema_version(probe) < SCHEMA_VERSION
            probe.close()
        except sqlite3.DatabaseError as exc:
            raise StorageCorruptionError(f"Database cannot be opened safely: {exc}") from exc
    if needs_backup:
        _backup_before_migration()

    try:
        with _LOCK:
            con = _connect_raw()
            try:
                con.execute("PRAGMA journal_mode=WAL")
                con.execute("BEGIN IMMEDIATE")
                _execute_schema_statements(con)
                # Migrate older v0.2 databases without deleting user data.
                _ensure_column(con, "memories", "origin_roots", "TEXT NOT NULL DEFAULT '[]'")
                _ensure_column(con, "memories", "idempotency_key", "TEXT")
                _ensure_column(con, "memories", "state_signature", "TEXT NOT NULL DEFAULT ''")
                _ensure_column(con, "memories", "request_fingerprint", "TEXT NOT NULL DEFAULT ''")
                _ensure_column(con, "audit_events", "event_signature", "TEXT NOT NULL DEFAULT ''")
                con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_idempotency ON memories(namespace,idempotency_key) WHERE idempotency_key IS NOT NULL")
                con.execute("INSERT INTO schema_meta(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(SCHEMA_VERSION),))
                _ensure_secret_binding(con)
                _ensure_runtime_mode(con)
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
    except sqlite3.IntegrityError as exc:
        raise StorageError(f"Database migration constraint failure: {exc}") from exc
    except sqlite3.DatabaseError as exc:
        msg = str(exc).lower()
        if "malformed" in msg or "corrupt" in msg:
            raise StorageCorruptionError(f"Database appears corrupt: {exc}") from exc
        raise StorageError(f"Database initialization failed: {exc}") from exc


@contextmanager
def connect(*, write: bool = False):
    """Open a SQLite transaction with clear busy/corruption classification.

    A process-level lock serialises writes; WAL still permits concurrent readers. SQLite's
    own busy timeout protects against a second MemoryGuard process or backup operation.
    """
    lock = _LOCK if write else _NullLock()
    with lock:
        con = None
        try:
            con = _connect_raw()
            con.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield con
            con.commit()
        except sqlite3.OperationalError as exc:
            if con is not None:
                try: con.rollback()
                except sqlite3.DatabaseError: pass
            msg = str(exc).lower()
            if "locked" in msg or "busy" in msg:
                raise StorageBusyError("MemoryGuard storage is temporarily busy; retry the operation") from exc
            raise StorageError(f"SQLite operational error: {exc}") from exc
        except sqlite3.DatabaseError as exc:
            if con is not None:
                try: con.rollback()
                except sqlite3.DatabaseError: pass
            msg = str(exc).lower()
            if "malformed" in msg or "corrupt" in msg or "not a database" in msg:
                raise StorageCorruptionError(f"MemoryGuard database corruption detected: {exc}") from exc
            raise StorageError(f"SQLite database error: {exc}") from exc
        except Exception:
            if con is not None:
                try: con.rollback()
                except sqlite3.DatabaseError: pass
            raise
        finally:
            if con is not None:
                con.close()


class _NullLock:
    def __enter__(self): return self
    def __exit__(self, *args): return False


def row_to_dict(row):
    if row is None:
        return None
    d = dict(row)
    for field, fallback in (("origin_roots", []), ("parent_ids", []), ("risk_signals", []), ("metadata", {})):
        if field in d and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except json.JSONDecodeError:
                d[field] = fallback
                d.setdefault("_decode_errors", []).append(field)
    return d


def backup_database(label: str = "manual") -> Path:
    dest_dir = config.backup_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_label = "".join(c for c in label if c.isalnum() or c in "-_" )[:40] or "manual"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = dest_dir / f"memoryguard-{safe_label}-{stamp}.db"
    try:
        with _LOCK:
            source = _connect_raw()
            target = sqlite3.connect(dest)
            with target:
                source.backup(target)
            source.close(); target.close()
            verify = sqlite3.connect(dest, timeout=5)
            try:
                quick = verify.execute("PRAGMA quick_check").fetchone()[0]
            finally:
                verify.close()
            if quick != "ok":
                raise sqlite3.DatabaseError(f"backup quick_check failed: {quick}")
        return dest
    except sqlite3.DatabaseError as exc:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        raise StorageError(f"Database backup failed: {exc}") from exc



def liveness() -> dict:
    """Cheap storage liveness check for frequent health probes.

    Deep `quick_check`/foreign-key verification belongs in diagnostics()/integrity and
    is intentionally not executed on every load-balancer or browser health request.
    """
    result = {"ok": False, "schema_version": None, "error": None}
    try:
        with connect(write=False) as con:
            con.execute("SELECT 1").fetchone()
            version = _schema_version(con)
        result.update(ok=(version == SCHEMA_VERSION), schema_version=version)
        if version != SCHEMA_VERSION:
            result["error"] = f"schema version {version} != expected {SCHEMA_VERSION}"
    except StorageError as exc:
        result["error"] = str(exc)
    return result

def diagnostics() -> dict:
    result = {
        "ok": False,
        "database": str(DB_PATH),
        "exists": DB_PATH.exists(),
        "schema_version": None,
        "quick_check": None,
        "foreign_key_violations": [],
        "secret_binding_ok": None,
        "runtime_mode": None,
        "runtime_mode_valid": None,
        "error": None,
    }
    try:
        with connect(write=False) as con:
            quick = con.execute("PRAGMA quick_check").fetchone()[0]
            fk = [dict(r) for r in con.execute("PRAGMA foreign_key_check").fetchall()]
            version = _schema_version(con)
            secret_binding_ok = _secret_binding_valid(con)
            runtime = runtime_mode_status(con)
        result.update(
            ok=(quick == "ok" and not fk and secret_binding_ok and runtime["valid"]),
            quick_check=quick, foreign_key_violations=fk, schema_version=version,
            secret_binding_ok=secret_binding_ok, runtime_mode=runtime["mode"], runtime_mode_valid=runtime["valid"],
        )
        if not secret_binding_ok:
            result["error"] = "configured signing secret does not match database binding"
        elif not runtime["valid"]:
            result["error"] = "runtime mode signature is invalid; MemoryGuard is fail-closed in lockdown"
    except StorageError as exc:
        result["error"] = str(exc)
    return result
