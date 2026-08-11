from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PORT_FILE = ROOT / ".memoryguard-port"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def base_url() -> str:
    direct = os.getenv("MEMORYGUARD_URL", "").strip().rstrip("/")
    if direct:
        parsed = urllib.parse.urlparse(direct)
        local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("MEMORYGUARD_URL must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and not local:
            raise RuntimeError("Refusing to send MemoryGuard data or credentials over non-local plaintext HTTP")
        return direct
    port = 43847
    if DEFAULT_PORT_FILE.exists():
        try:
            port = int(DEFAULT_PORT_FILE.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as exc:
            raise RuntimeError(".memoryguard-port is invalid; rerun installation diagnostics") from exc
    if not 1024 <= port <= 65535:
        raise RuntimeError("MemoryGuard port is outside the allowed range")
    return f"http://127.0.0.1:{port}"


def request(path: str, payload: dict | None = None, method: str = "GET", *, operator: bool = False):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    key = os.getenv("MEMORYGUARD_API_KEY", "").strip()
    if key:
        headers["X-MemoryGuard-Key"] = key
    if operator:
        operator_key = os.getenv("MEMORYGUARD_OPERATOR_KEY", "").strip()
        if not operator_key:
            raise RuntimeError("this administrative command requires MEMORYGUARD_OPERATOR_KEY; do not provide it to an autonomous runtime agent")
        headers["X-MemoryGuard-Operator-Key"] = operator_key
    data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8") if payload is not None else None
    last_error: Exception | None = None
    for attempt in range(3):
        req = urllib.request.Request(base_url() + path, data=data, method=method, headers=headers)
        try:
            with _OPENER.open(req, timeout=10) as response:
                raw = response.read(2_000_000)
                if response.read(1):
                    raise RuntimeError("MemoryGuard response exceeded the CLI safety limit")
                result = json.loads(raw.decode("utf-8"))
                if not isinstance(result, dict):
                    raise RuntimeError("MemoryGuard returned non-object JSON")
                return result
        except urllib.error.HTTPError as exc:
            body = exc.read(1000).decode("utf-8", errors="replace")
            if exc.code in {429, 502, 503, 504} and attempt < 2:
                time.sleep(0.25 * (2 ** attempt))
                continue
            raise RuntimeError(f"MemoryGuard HTTP {exc.code}: {body}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(0.25 * (2 ** attempt))
                continue
            break
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("MemoryGuard returned invalid JSON") from exc
    raise RuntimeError(f"MemoryGuard unavailable at {base_url()} after retries: {last_error}")


def main() -> int:
    ap = argparse.ArgumentParser(description="MemoryGuard agent-safe CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("store")
    s.add_argument("content")
    s.add_argument("--source-type", default="tool", choices=["web","email","document","api","tool","unknown_external"])
    s.add_argument("--source-uri")
    s.add_argument("--namespace", default=os.getenv("MEMORYGUARD_NAMESPACE", "agent"))
    s.add_argument("--idempotency-key")

    r = sub.add_parser("recall")
    r.add_argument("query")
    r.add_argument("--namespace", default=os.getenv("MEMORYGUARD_NAMESPACE", "agent"))
    r.add_argument("--limit", type=int, default=8)

    sc = sub.add_parser("scan")
    sc.add_argument("content")
    sc.add_argument("--source-type", default="unknown_external", choices=["web","email","document","api","tool","unknown_external","derived"])

    ac = sub.add_parser("check-action")
    ac.add_argument("action")
    ac.add_argument("--risk", default="medium", choices=["low","medium","high","critical"])
    ac.add_argument("--namespace", default=os.getenv("MEMORYGUARD_NAMESPACE", "agent"))
    ac.add_argument("--context-ids", default="")
    ac.add_argument("--authorization-ids", default="")

    st = sub.add_parser("stats")
    st.add_argument("--namespace", default=os.getenv("MEMORYGUARD_NAMESPACE", "agent"))
    sub.add_parser("integrity")
    sub.add_parser("health")

    args = ap.parse_args()
    if args.cmd == "store":
        result = request("/api/v1/memories", {
            "content": args.content,
            "source_type": args.source_type,
            "source_uri": args.source_uri,
            "namespace": args.namespace,
            "created_by": "agent-cli",
            "idempotency_key": args.idempotency_key,
        }, "POST")
    elif args.cmd == "recall":
        result = request("/api/v1/search", {"query": args.query, "namespace": args.namespace, "limit": args.limit}, "POST")
    elif args.cmd == "scan":
        result = request("/api/v1/scan", {"content": args.content, "source_type": args.source_type}, "POST")
    elif args.cmd == "check-action":
        def parse_ids(raw: str) -> list[int]:
            if not raw.strip():
                return []
            try:
                values = [int(x.strip()) for x in raw.split(",") if x.strip()]
            except ValueError as exc:
                raise RuntimeError("memory ID lists must be comma-separated integers") from exc
            if any(x <= 0 for x in values) or len(set(values)) != len(values):
                raise RuntimeError("memory ID lists must contain unique positive integers")
            return values
        result = request("/api/v1/action-check", {
            "action": args.action, "action_risk": args.risk, "namespace": args.namespace,
            "context_memory_ids": parse_ids(args.context_ids),
            "authorization_memory_ids": parse_ids(args.authorization_ids),
            "actor": "agent-cli",
        }, "POST")
    elif args.cmd == "stats":
        result = request("/api/v1/stats?" + urllib.parse.urlencode({"namespace": args.namespace}))
    elif args.cmd == "integrity":
        result = request("/api/v1/integrity", operator=True)
    else:
        result = request("/health")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(2)
