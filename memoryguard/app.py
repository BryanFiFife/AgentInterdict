from __future__ import annotations

import hmac
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config, db, service
from .errors import ConflictError, IntegrityError, MemoryGuardError, StorageBusyError, StorageCorruptionError, StorageError, ValidationError
from .licensing import get_license_status
from .models import ActionCheckRequest, IngestRequest, PromoteRequest, ReviewRequest, ReviseRequest, RuntimeModeRequest, ScanRequest, SearchRequest
from .security import DEMO_SECRET, signing_secret_status

log = logging.getLogger("memoryguard")
logging.basicConfig(level=os.getenv("MEMORYGUARD_LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")

MAX_HTTP_BODY = config.env_int("MEMORYGUARD_MAX_HTTP_BODY", 1_200_000, 65_536, 10_000_000)


@asynccontextmanager
async def lifespan(app: FastAPI):
    secret_status = signing_secret_status()
    if not secret_status["usable"]:
        raise RuntimeError("MemoryGuard refuses to start with a missing, demo, or short signing secret; run the installer or set MEMORYGUARD_SECRET to a random 32+ byte value")
    api_key = config.api_key()
    if api_key and len(api_key.encode("utf-8")) < 32:
        raise RuntimeError("MEMORYGUARD_API_KEY must be at least 32 bytes when configured")
    operator_key = config.operator_key()
    if len(operator_key.encode("utf-8")) < 32:
        raise RuntimeError("MEMORYGUARD_OPERATOR_KEY must be configured with at least 32 bytes; run the installer")
    if config.is_remote_bind() and not api_key:
        raise RuntimeError("MemoryGuard refuses a configured remote bind without MEMORYGUARD_API_KEY")
    db.init_db()
    diag = db.diagnostics()
    if not diag["ok"]:
        raise RuntimeError("MemoryGuard storage diagnostics failed; startup aborted to protect persistent state")
    yield


app = FastAPI(
    title="MemoryGuard",
    version=config.VERSION,
    description="Origin-bound security gateway for persistent AI agent memory",
    lifespan=lifespan,
)
STATIC = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    request_id = secrets.token_hex(8)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_HTTP_BODY:
                return JSONResponse({"detail": "request body too large", "request_id": request_id}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "invalid content-length", "request_id": request_id}, status_code=400)

    required_key = config.api_key()
    if required_key and request.url.path.startswith("/api/v1/"):
        supplied = request.headers.get("x-memoryguard-key", "")
        if not supplied or not hmac.compare_digest(supplied, required_key):
            return JSONResponse({"detail": "MemoryGuard API key required", "request_id": request_id}, status_code=401)

    # Content-Length is not mandatory (for example with Transfer-Encoding: chunked),
    # so bound the stream before FastAPI/Pydantic parses it. The accumulated body is
    # capped at MAX_HTTP_BODY and replayed to downstream request parsing.
    if request.method in {"POST", "PUT", "PATCH"}:
        chunks: list[bytes] = []
        received = 0
        try:
            async for chunk in request.stream():
                received += len(chunk)
                if received > MAX_HTTP_BODY:
                    return JSONResponse({"detail": "request body too large", "request_id": request_id}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        except Exception:
            log.exception("Failed while reading request body request_id=%s path=%s", request_id, request.url.path)
            return JSONResponse({"detail": "invalid request body", "request_id": request_id}, status_code=400)

    try:
        response = await call_next(request)
    except Exception:
        log.exception("Unhandled request failure request_id=%s path=%s", request_id, request.url.path)
        return JSONResponse({"detail": "internal MemoryGuard error", "request_id": request_id}, status_code=500)

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response


@app.exception_handler(RequestValidationError)
async def request_validation_handler(request: Request, exc: RequestValidationError):
    # Do not serialize Pydantic's raw ctx objects (which may contain ValueError instances).
    safe_errors = []
    for item in exc.errors():
        safe_errors.append({
            "type": str(item.get("type", "validation_error")),
            "loc": [str(x) for x in item.get("loc", ())],
            "msg": str(item.get("msg", "invalid value")),
        })
    return JSONResponse({"detail": "invalid request", "errors": safe_errors}, status_code=422)


@app.exception_handler(ValidationError)
async def validation_handler(request: Request, exc: ValidationError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(ConflictError)
async def conflict_handler(request: Request, exc: ConflictError):
    return JSONResponse({"detail": str(exc)}, status_code=409)


@app.exception_handler(StorageBusyError)
async def storage_busy_handler(request: Request, exc: StorageBusyError):
    return JSONResponse({"detail": str(exc), "retryable": True}, status_code=503, headers={"Retry-After": "1"})


@app.exception_handler(StorageCorruptionError)
async def storage_corrupt_handler(request: Request, exc: StorageCorruptionError):
    log.error("Storage corruption: %s", exc)
    return JSONResponse({"detail": "storage integrity failure; stop writes and restore from a verified backup", "retryable": False}, status_code=500)


@app.exception_handler(StorageError)
async def storage_handler(request: Request, exc: StorageError):
    log.error("Storage failure: %s", exc)
    return JSONResponse({"detail": "storage operation failed", "retryable": False}, status_code=500)


def _require_operator(request: Request) -> None:
    expected = config.operator_key()
    supplied = request.headers.get("x-memoryguard-operator-key", "")
    if len(expected.encode("utf-8")) < 32:
        raise HTTPException(503, "MemoryGuard operator authority is not configured")
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(403, "MemoryGuard operator key required")


@app.get("/")
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    live = db.liveness()
    public_storage = {"ok": live["ok"], "schema_version": live.get("schema_version")}
    payload = {"ok": live["ok"], "service": "memoryguard", "version": config.VERSION, "storage": public_storage}
    return JSONResponse(payload, status_code=200 if live["ok"] else 503)


@app.get("/api/v1/license")
def license_status():
    return get_license_status().as_dict()


@app.post("/api/v1/scan")
def scan(req: ScanRequest):
    return service.scan_candidate(**req.model_dump())


@app.post("/api/v1/action-check")
def action_check(req: ActionCheckRequest):
    return service.action_check(**req.model_dump())


@app.get("/api/v1/system")
def system_status():
    secret = os.getenv("MEMORYGUARD_SECRET", DEMO_SECRET.decode()).encode()
    live = db.liveness()
    return {
        "version": config.VERSION,
        "port": config.port(),
        "host": config.bind_host(),
        "database_ok": live["ok"],
        "schema_version": live.get("schema_version"),
        "signing_secret_is_demo": secret == DEMO_SECRET,
        "api_key_enabled": bool(config.api_key()),
        "operator_key_configured": len(config.operator_key().encode("utf-8")) >= 32,
        "remote_bind_without_api_key": config.is_remote_bind() and not bool(config.api_key()),
        "runtime_mode": service.runtime_mode(),
        "license": get_license_status().as_dict(),
    }


@app.post("/api/v1/memories")
def ingest(req: IngestRequest, request: Request):
    privileged = req.source_type in {"human", "human_verified", "system_config"} or req.explicit_human_authorization
    if privileged:
        _require_operator(request)
    return service.ingest(trusted_ingest=privileged, **req.model_dump())


@app.get("/api/v1/memories")
def list_memories(
    request: Request,
    namespace: str = Query("default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    status: Literal["allowed","review","quarantined","superseded"] | None = None,
    limit: int = Query(100, ge=1, le=500),
):
    _require_operator(request)
    return service.list_memories(namespace, status, limit)


@app.get("/api/v1/memories/{memory_id}")
def get_memory(memory_id: int, request: Request):
    _require_operator(request)
    m = service.get(memory_id)
    if not m:
        raise HTTPException(404, "memory not found")
    return m


@app.post("/api/v1/search")
def search(req: SearchRequest, request: Request):
    if req.include_review:
        _require_operator(request)
    return {"items": service.search(**req.model_dump())}


@app.post("/api/v1/memories/{memory_id}/review")
def review(memory_id: int, req: ReviewRequest, request: Request):
    _require_operator(request)
    try:
        return service.review(memory_id, **req.model_dump())
    except KeyError:
        raise HTTPException(404, "memory not found")


@app.post("/api/v1/memories/{memory_id}/authority")
def promote(memory_id: int, req: PromoteRequest, request: Request):
    _require_operator(request)
    try:
        return service.promote(memory_id, **req.model_dump())
    except KeyError:
        raise HTTPException(404, "memory not found")


@app.post("/api/v1/memories/{memory_id}/revise")
def revise(memory_id: int, req: ReviseRequest, request: Request):
    _require_operator(request)
    try:
        return service.revise(memory_id, **req.model_dump())
    except KeyError:
        raise HTTPException(404, "memory not found")


@app.post("/api/v1/memories/{memory_id}/rollback")
def rollback(
    memory_id: int, request: Request, actor: str = Query("reviewer", min_length=1, max_length=160),
    idempotency_key: str | None = Query(default=None, min_length=8, max_length=200),
):
    _require_operator(request)
    try:
        return service.rollback(memory_id, actor=actor, idempotency_key=idempotency_key)
    except KeyError:
        raise HTTPException(404, "memory not found")


@app.get("/api/v1/memories/{memory_id}/contamination")
def contamination(memory_id: int, request: Request):
    _require_operator(request)
    try:
        return service.contamination_report(memory_id)
    except KeyError:
        raise HTTPException(404, "memory not found")


@app.post("/api/v1/memories/{memory_id}/contain")
def contain(memory_id: int, request: Request, actor: str = Query("dashboard", min_length=1, max_length=160), reason: str = Query("incident containment", max_length=4000)):
    _require_operator(request)
    try:
        return service.contain(memory_id, actor=actor, reason=reason)
    except KeyError:
        raise HTTPException(404, "memory not found")


@app.get("/api/v1/runtime-mode")
def runtime_mode(request: Request):
    _require_operator(request)
    return service.runtime_mode()


@app.post("/api/v1/runtime-mode")
def set_runtime_mode(req: RuntimeModeRequest, request: Request):
    _require_operator(request)
    return service.set_runtime_mode(**req.model_dump())


@app.get("/api/v1/stats")
def stats(namespace: str = Query("default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")):
    return service.stats(namespace)


@app.get("/api/v1/audit")
def audit(request: Request, limit: int = Query(100, ge=1, le=500)):
    _require_operator(request)
    return service.audit(limit)


@app.get("/api/v1/integrity")
def integrity(request: Request):
    _require_operator(request)
    return service.verify_integrity()


@app.post("/api/v1/backup")
def backup(request: Request, actor: str = Query("dashboard", min_length=1, max_length=160)):
    _require_operator(request)
    return service.backup(actor)
