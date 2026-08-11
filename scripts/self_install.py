from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PORTS = [43847, 43853, 43909, 45137, 47321, 49157]
CORE_IMPORTS = ["fastapi", "uvicorn", "pydantic", "httpx", "cryptography"]
SECURE_RUNTIME_BOUNDS = {
    "fastapi": ("0.115", "1"),
    "uvicorn": ("0.30", "1"),
    "pydantic": ("2.8", "3"),
    "httpx": ("0.27", "1"),
    "cryptography": ("50.0.0", "51"),
    "starlette": ("0.40.0", "0.51.0"),
    "h11": ("0.16.0", "1"),
    "packaging": ("24.0", "26"),
}




def atomic_write_text(path: Path, text: str, *, mode: int | None = None) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing to replace symlinked installer state file: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent, text=True)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass

def run(cmd, *, env=None, check=True):
    print("+", " ".join(map(str, cmd)))
    return subprocess.run([str(x) for x in cmd], cwd=ROOT, env=env, check=check)


def can_import(python_exe: str | Path, modules: list[str]) -> bool:
    code = ";".join(f"import {m}" for m in modules)
    return subprocess.run(
        [str(python_exe), "-c", code],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def secure_runtime_compatible(python_exe: str | Path) -> tuple[bool, str]:
    """Require fallback runtimes to satisfy the release's audited version bounds."""
    bounds_json = json.dumps(SECURE_RUNTIME_BOUNDS)
    code = f"""
import importlib.metadata as md
import json
try:
    from packaging.version import Version
except Exception as exc:
    print(json.dumps({{"ok": False, "reason": "packaging unavailable: " + str(exc)}}))
    raise SystemExit(2)
bounds = json.loads({bounds_json!r})
for name, pair in bounds.items():
    minimum, maximum = pair
    try:
        current = Version(md.version(name))
    except Exception as exc:
        print(json.dumps({{"ok": False, "reason": name + " unavailable: " + str(exc)}}))
        raise SystemExit(2)
    if current < Version(minimum) or current >= Version(maximum):
        print(json.dumps({{"ok": False, "reason": f"{{name}} {{current}} outside secure range >= {{minimum}}, < {{maximum}}"}}))
        raise SystemExit(2)
print(json.dumps({{"ok": True, "reason": "secure runtime dependency bounds satisfied"}}))
"""
    result = subprocess.run(
        [str(python_exe), "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    message = (result.stdout or result.stderr or "runtime dependency check failed").strip()
    return result.returncode == 0, message


def find_python() -> str:
    # Prefer the interpreter already executing this installer. This supports Windows
    # systems where `py -3` launched us but `python` is not on PATH.
    candidates = [sys.executable, shutil.which("python3"), shutil.which("python")]
    seen = set()
    for exe in candidates:
        if not exe or exe in seen:
            continue
        seen.add(exe)
        probe = subprocess.run(
            [exe, "-c", "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 2)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return str(exe)
    raise RuntimeError("Python 3.10+ is required")


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def venv_python() -> Path:
    return ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def create_venv(py: str) -> Path:
    vdir = ROOT / ".venv"
    if vdir.exists():
        shutil.rmtree(vdir)
    run([py, "-m", "venv", str(vdir)])
    return venv_python()


def _installed_runtime_ok(py: str | Path) -> tuple[bool, str]:
    if not can_import(py, CORE_IMPORTS):
        return False, "one or more core imports are unavailable"
    return secure_runtime_compatible(py)


def ensure_core_dependencies(py: str) -> tuple[Path, list[str]]:
    warnings: list[str] = []
    vp = venv_python()
    if not vp.exists():
        vp = create_venv(py)

    pinned = ROOT / "requirements-tested.txt"
    if pinned.exists():
        install = run([vp, "-m", "pip", "install", "--disable-pip-version-check", "-r", pinned.name], check=False)
        ok, detail = _installed_runtime_ok(vp) if install.returncode == 0 else (False, "pinned install failed")
        if ok:
            return vp, warnings
        warnings.append(f"Pinned release dependencies were unavailable or invalid ({detail}); attempting compatible secure ranges.")

    install = run([vp, "-m", "pip", "install", "--disable-pip-version-check", "-r", "requirements.txt"], check=False)
    ok, detail = _installed_runtime_ok(vp) if install.returncode == 0 else (False, "compatible-range install failed")
    if ok:
        return vp, warnings

    # Restricted/offline environments may already provide compatible packages, but
    # imports alone are insufficient. Refuse a fallback below the security floor.
    base_ok, base_detail = _installed_runtime_ok(py)
    if base_ok:
        warnings.append(
            "Package installation failed; using the already-installed Python runtime only after verifying all release security-version bounds."
        )
        try:
            shutil.rmtree(ROOT / ".venv")
        except OSError:
            pass
        return Path(py), warnings
    raise RuntimeError(
        "Core dependency installation failed and the preinstalled runtime does not meet the secure release baseline: "
        + base_detail
    )


def ensure_mcp(vp: Path) -> tuple[bool, str | None]:
    if can_import(vp, ["mcp"]):
        return True, None
    result = run([vp, "-m", "pip", "install", "--disable-pip-version-check", "mcp[cli]>=2,<3"], check=False)
    if result.returncode == 0 and can_import(vp, ["mcp"]):
        return True, None
    return False, (
        "MCP v2 dependency could not be installed; core AgentInterdict remains usable through "
        "Hermes/OpenClaw/REST/CLI integrations."
    )


def ensure_test_dependency(vp: Path) -> None:
    if can_import(vp, ["pytest"]):
        return
    result = run([vp, "-m", "pip", "install", "--disable-pip-version-check", "pytest>=8,<10"], check=False)
    if result.returncode != 0 or not can_import(vp, ["pytest"]):
        raise RuntimeError(
            "pytest is required for mandatory installation verification; use --skip-tests only when you intentionally accept reduced verification"
        )


def ensure_local_key(filename: str, label: str) -> str:
    path = ROOT / filename
    if path.is_symlink():
        raise RuntimeError(f"existing {filename} is a symlink; refusing to use it for {label}")
    if not path.exists():
        atomic_write_text(path, secrets.token_hex(32), mode=0o600)
    if not path.is_file() or path.stat().st_size > 4096:
        raise RuntimeError(f"existing {filename} is not a valid small {label} file; inspect it instead of replacing it")
    value = path.read_text(encoding="utf-8").strip()
    if len(value.encode("utf-8")) < 32:
        raise RuntimeError(f"existing {filename} is unexpectedly short; inspect it instead of silently replacing it")
    return value


def ensure_secret() -> str:
    return ensure_local_key(".agentinterdict-secret", "signing secret")


def ensure_operator_key() -> str:
    return ensure_local_key(".agentinterdict-operator-key", "operator key")


def choose_port(explicit: int | None) -> int:
    if explicit is not None:
        if not 1024 <= explicit <= 65535:
            raise RuntimeError("port must be between 1024 and 65535")
        if not port_available(explicit):
            raise RuntimeError(f"requested port {explicit} is already in use")
        return explicit
    for candidate in DEFAULT_PORTS:
        if port_available(candidate):
            return candidate
    raise RuntimeError("no standard AgentInterdict fallback port is available; supply --port")


def main() -> int:
    ap = argparse.ArgumentParser(description="Install and verify AgentInterdict from a single extracted folder")
    ap.add_argument("--port", type=int)
    ap.add_argument("--with-mcp", action="store_true", help="Attempt to install the optional MCP v2 integration")
    ap.add_argument("--require-mcp", action="store_true", help="Fail installation if MCP v2 cannot be installed")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--start", action="store_true")
    args = ap.parse_args()
    if args.require_mcp:
        args.with_mcp = True

    py = find_python()
    vp, warnings = ensure_core_dependencies(py)
    mcp_ok = False
    if args.with_mcp:
        mcp_ok, warning = ensure_mcp(vp)
        if warning:
            warnings.append(warning)
        if args.require_mcp and not mcp_ok:
            raise RuntimeError("MCP was explicitly required but could not be installed")

    secret = ensure_secret()
    operator_key = ensure_operator_key()
    port = choose_port(args.port)
    atomic_write_text(ROOT / ".agentinterdict-port", str(port), mode=0o600)
    env = os.environ.copy()
    env.update(
        {
            "AGENTINTERDICT_SECRET": secret,
            "AGENTINTERDICT_OPERATOR_KEY": operator_key,
            "AGENTINTERDICT_DB": str(ROOT / "agentinterdict.db"),
            "AGENTINTERDICT_PORT": str(port),
            "AGENTINTERDICT_HOST": "127.0.0.1",
        }
    )

    run([vp, "scripts/doctor.py"], env=env)
    tests_passed = None
    if not args.skip_tests:
        ensure_test_dependency(vp)
        run([vp, "-m", "pytest", "-q"], env=env)
        tests_passed = True

    state = {
        "installed": True,
        "version": "0.4.0",
        "root": str(ROOT),
        "dashboard": f"http://127.0.0.1:{port}",
        "api_docs": f"http://127.0.0.1:{port}/docs",
        "port": port,
        "mcp_dependencies": mcp_ok,
        "runtime_python": str(vp),
        "operator_key_file": str(ROOT / ".agentinterdict-operator-key"),
        "tests_passed": tests_passed,
        "warnings": warnings,
        "platform": platform.platform(),
    }
    atomic_write_text(ROOT / "installation-result.json", json.dumps(state, indent=2) + "\n", mode=0o600)
    print(json.dumps(state, indent=2))

    if args.start:
        os.execve(
            str(vp),
            [str(vp), "-m", "uvicorn", "agentinterdict.app:app", "--host", "127.0.0.1", "--port", str(port)],
            env,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"INSTALL FAILED: command returned {exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode)
    except Exception as exc:
        print(f"INSTALL FAILED: {exc}", file=sys.stderr)
        raise SystemExit(2)
