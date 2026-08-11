#!/usr/bin/env python3
"""Activate/refresh a AgentInterdict paid lease from the vendor control plane."""
from __future__ import annotations

import argparse
import getpass
import os
import json
import secrets
import tempfile
import time
from pathlib import Path

import httpx

from agentinterdict.licensing import verify_license_token

HOME = Path.home() / ".agentinterdict"
INSTALL_ID_FILE = HOME / "installation_id"
LICENSE_FILE = HOME / "license.mglic"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def main() -> int:
    ap = argparse.ArgumentParser(description="Activate or refresh AgentInterdict")
    ap.add_argument("--server", required=True, help="Vendor control-plane base URL (HTTPS required except localhost development)")
    ap.add_argument("--license-key", help="Customer activation key (prefer prompt or AGENTINTERDICT_ACTIVATION_KEY to avoid shell history)")
    args = ap.parse_args()

    base = args.server.rstrip("/")
    if not (base.startswith("https://") or base.startswith("http://127.0.0.1") or base.startswith("http://localhost")):
        raise SystemExit("Refusing activation over insecure non-local HTTP")
    license_key = args.license_key or os.getenv("AGENTINTERDICT_ACTIVATION_KEY")
    if not license_key:
        try:
            license_key = getpass.getpass("AgentInterdict activation key: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise SystemExit("Activation cancelled; no lease was changed") from exc
    license_key = license_key.strip()
    if len(license_key) > 512 or not license_key or any(ord(ch) < 32 for ch in license_key):
        raise SystemExit("Invalid activation key")

    HOME.mkdir(parents=True, exist_ok=True)
    if INSTALL_ID_FILE.exists():
        install_id = INSTALL_ID_FILE.read_text(encoding="utf-8").strip()
        if not install_id or len(install_id) > 200:
            raise SystemExit("Existing installation_id is invalid; inspect it before retrying")
    else:
        install_id = "install_" + secrets.token_urlsafe(24)
        _atomic_write(INSTALL_ID_FILE, install_id)

    last_error = None
    data = None
    for attempt in range(3):
        try:
            with httpx.Client(timeout=httpx.Timeout(20.0, connect=8.0), follow_redirects=False) as client:
                with client.stream("POST", base + "/v1/lease", json={"license_key": license_key, "installation_id": install_id}) as response:
                    if response.status_code in {429, 502, 503, 504} and attempt < 2:
                        response.read()
                        time.sleep(0.4 * (2 ** attempt))
                        continue
                    response.raise_for_status()
                    chunks = []
                    received = 0
                    for chunk in response.iter_bytes():
                        received += len(chunk)
                        if received > 65_536:
                            raise ValueError("activation response exceeds 64 KiB safety limit")
                        chunks.append(chunk)
                    data = json.loads(b"".join(chunks).decode("utf-8"))
            break
        except (httpx.HTTPError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < 2 and isinstance(exc, (httpx.TransportError, httpx.TimeoutException)):
                time.sleep(0.4 * (2 ** attempt))
                continue
            raise SystemExit(f"Activation failed without changing the current lease: {exc}") from exc
    if data is None:
        raise SystemExit(f"Activation failed without changing the current lease: {last_error}")


    if not isinstance(data, dict):
        raise SystemExit("Activation server returned an invalid response")
    token = data.get("token")
    plan = data.get("plan")
    offline_until = data.get("offline_until")
    if not isinstance(token, str) or token.count(".") != 1 or len(token) > 32768:
        raise SystemExit("Activation server returned an invalid signed lease")
    if not isinstance(plan, str) or not isinstance(offline_until, str):
        raise SystemExit("Activation server response is missing required entitlement fields")

    verified = verify_license_token(token, source="activation-response", installation_id=install_id)
    if not verified.valid or verified.plan != plan:
        raise SystemExit(f"Activation response failed local cryptographic verification: {verified.reason}")

    _atomic_write(LICENSE_FILE, token)
    print(f"Activated {plan} until {offline_until}")
    print(f"Lease saved to {LICENSE_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
