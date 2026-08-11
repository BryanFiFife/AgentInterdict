from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentinterdict import config, db, service
from agentinterdict.security import DEMO_SECRET, signing_secret_status


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentInterdict diagnostics")
    ap.add_argument("--startup", action="store_true", help="Run checks suitable immediately before server startup")
    args = ap.parse_args()

    failures = []
    warnings = []
    try:
        db.init_db()
    except Exception as exc:
        failures.append(f"database init: {exc}")

    diag = db.diagnostics()
    if not diag.get("ok"):
        failures.append(f"database diagnostics: {diag}")

    secret_status = signing_secret_status()
    if not secret_status["usable"]:
        failures.append("AGENTINTERDICT_SECRET must be a non-demo random value of at least 32 bytes")
    api_key = config.api_key()
    if api_key and len(api_key.encode("utf-8")) < 32:
        failures.append("AGENTINTERDICT_API_KEY must be at least 32 bytes when configured")
    if len(config.operator_key().encode("utf-8")) < 32:
        failures.append("AGENTINTERDICT_OPERATOR_KEY must be at least 32 bytes")
    if config.is_remote_bind() and not api_key:
        failures.append("remote bind requires AGENTINTERDICT_API_KEY")
    if args.startup and not port_available(config.port()):
        failures.append(f"port {config.port()} is already occupied")

    try:
        integrity = service.verify_integrity()
        if not integrity["ok"]:
            failures.append(f"integrity verification: {integrity['problems']}")
        warnings.extend(x.get("warning", "") for x in integrity.get("warnings", []) if x.get("warning"))
    except Exception as exc:
        failures.append(f"integrity verification crashed: {exc}")

    print(f"AgentInterdict doctor v{config.VERSION}")
    print(f"database: {db.DB_PATH}")
    print(f"port: {config.port()}")
    for w in warnings:
        print(f"WARNING: {w}")
    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 2
    print("OK: diagnostics passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
