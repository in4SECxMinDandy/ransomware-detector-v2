"""
api/main.py
===========
FastAPI application for Ransomware Detector v2 REST API.

Endpoints:
  POST /api/v1/auth/token          — Get JWT token
  POST /api/v1/scan/file           — Scan directory
  POST /api/v1/scan/hash          — Query VirusTotal hash
  POST /api/v1/scan/office         — Scan Office documents
  GET  /api/v1/status             — System status
  GET  /api/v1/alerts             — Recent alerts
  GET  /api/v1/health             — Health check
  GET  /api/v1/honeypots          — Honeypot status
  POST /api/v1/honeypots/deploy   — Deploy honeypots
  GET  /api/v1/honeypots/history  — Access history
  DELETE /api/v1/honeypots       — Remove honeypots
  POST /api/v1/reports/generate   — Generate report
  GET  /api/v1/reports/{id}/download — Download report

Authentication:
  - JWT Bearer token (from /auth/token)
  - API Key via X-API-Key header

Run:
  uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
"""

import os
import sys
import time
import logging
import threading
import collections
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from typing import Dict, Any, Deque

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

# ─── Add project root to path ──────────────────────────────────────────────────

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ─── API Routers ──────────────────────────────────────────────────────────────

from starlette import status as http_status  # noqa: E402
from api.routers import scan, status as status_router, honeypots, reports  # noqa: E402
from api.auth import (  # noqa: E402
    authenticate_user, create_access_token, get_current_user, require_admin,
)
from api.schemas import (  # noqa: E402
    TokenResponse,
    APIKeyCreate,
    APIKeyResponse,
)

# ─── Logging ─────────────────────────────────────────────────────────────────

logger = logging.getLogger("api.main")


# ─── Lifespan (startup/shutdown) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for FastAPI app."""
    # Startup
    logger.info("Ransomware Detector API v2.0 starting...")

    # Ensure directories exist
    os.makedirs("data", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    # Initialize core modules lazily
    try:
        from core.logger_setup import setup_logging
        setup_logging()
        logger.info("Logging initialized")
    except Exception as e:
        logger.warning(f"Failed to setup logging: {e}")

    yield

    # Shutdown
    logger.info("Ransomware Detector API shutting down...")


# ─── FastAPI App ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="Ransomware Detector API",
    description=(
        "REST API for Ransomware Detector v2. "
        "Provides file scanning, threat intelligence, honeypot management, "
        "and ML feedback capabilities."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware — allowed_origins configured via data/config.json[api.allowed_origins]
# IMPORTANT: never combine allow_origins=["*"] with allow_credentials=True (browser
# enforcement will reject the response anyway, and any subdomain XSS becomes a CSRF).
try:
    from core.config_manager import config as _config
    _allowed_origins = _config.get("api.allowed_origins", ["http://localhost:3000"]) or []
except Exception:
    _allowed_origins = ["http://localhost:3000"]

if not _allowed_origins or _allowed_origins == ["*"]:
    logger.warning(
        "api.allowed_origins is empty or '*'; refusing wildcard CORS — "
        "falling back to http://localhost:3000."
    )
    _allowed_origins = ["http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

# ─── Rate limiter for /auth/token (defends against credential stuffing) ───────
_AUTH_RATE_LIMIT_LOCK = threading.Lock()
_AUTH_RATE_LIMIT_HITS: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
_AUTH_RATE_LIMIT_WINDOW_S = 60.0


def _enforce_auth_rate_limit(request: Request) -> None:
    """Sliding-window per-IP rate limiter for the auth endpoint."""
    try:
        from core.config_manager import config as _cfg
        per_minute = int(_cfg.get("api.auth_rate_limit_per_minute", 10))
    except Exception:
        per_minute = 10
    if per_minute <= 0:
        return  # disabled
    client_ip = (request.client.host if request.client else "unknown")
    now = time.monotonic()
    with _AUTH_RATE_LIMIT_LOCK:
        bucket = _AUTH_RATE_LIMIT_HITS[client_ip]
        # Drop expired hits
        cutoff = now - _AUTH_RATE_LIMIT_WINDOW_S
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= per_minute:
            retry_after = int(_AUTH_RATE_LIMIT_WINDOW_S - (now - bucket[0])) + 1
            raise HTTPException(
                status_code=429,
                detail="Too many authentication attempts; slow down.",
                headers={"Retry-After": str(retry_after)},
            )
        bucket.append(now)

# Include routers
app.include_router(scan.router, prefix="/api/v1")
app.include_router(status_router.router, prefix="/api/v1")
app.include_router(honeypots.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


# ─── Auth Endpoints ──────────────────────────────────────────────────────────

@app.post("/api/v1/auth/token", response_model=TokenResponse, tags=["Auth"])
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    Authenticate with username/password and get JWT access token.

    Rate limited per-IP (default 10 attempts/minute, configurable via
    ``api.auth_rate_limit_per_minute``).
    """
    _enforce_auth_rate_limit(request)
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from core.config_manager import config
    expire_minutes = config.get("api.access_token_expire_minutes", 60)
    access_token_expires = timedelta(minutes=expire_minutes)

    access_token = create_access_token(
        data={
            "sub": user["username"],
            "role": user.get("role", "reader"),
            "type": "jwt",
        },
        expires_delta=access_token_expires,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expire_minutes * 60,
        role=user.get("role", "reader"),
    )


@app.post("/api/v1/auth/apikey", response_model=APIKeyResponse, tags=["Auth"])
async def create_api_key(
    request: APIKeyCreate,
    current_user: Dict[str, Any] = Depends(require_admin),
):
    """
    Create a new API key.

    Persists the key to ``data/config.json`` under ``api.api_keys`` so that
    the value can be used for subsequent requests via the ``X-API-Key``
    header. Requires admin role.
    """
    import secrets as _secrets
    from core.config_manager import config as _cfg

    key = _secrets.token_urlsafe(32)
    role_value = request.role.value if hasattr(request.role, "value") else str(request.role)
    name = request.name or f"key-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    created_at = datetime.now(timezone.utc).isoformat()

    keys = _cfg.get("api.api_keys", {}) or {}
    keys[name] = {
        "key": key,
        "name": name,
        "role": role_value,
        "created_at": created_at,
        "disabled": False,
    }
    if not _cfg.set("api.api_keys", keys, persist=True):
        logger.error("Failed to persist API key %r to config", name)
        raise HTTPException(status_code=500, detail="Failed to persist API key")

    return APIKeyResponse(
        key=key,
        name=name,
        role=role_value,
        created_at=created_at,
    )


@app.get("/api/v1/auth/me", response_model=Dict[str, Any], tags=["Auth"])
async def get_current_user_info(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get current authenticated user information.
    """
    return {
        "username": current_user.get("username") or current_user.get("name"),
        "role": current_user.get("role", "reader"),
        "type": current_user.get("type", "unknown"),
    }


# ─── Root endpoint ────────────────────────────────────────────────────────────

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint — API info."""
    return {
        "name": "Ransomware Detector API",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/api/v1/health",
        "status": "/api/v1/status",
    }


@app.get("/ping", tags=["Root"])
async def ping():
    """Simple ping endpoint."""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ─── Global Exception Handler ────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler that returns a proper JSON 500 response.

    Stacktraces and exception messages may leak filesystem paths or secrets,
    so by default the client only sees a generic message. Set
    ``api.expose_internal_errors=true`` (and only in dev) to include
    ``detail``.
    """
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    try:
        from core.config_manager import config as _cfg
        expose = bool(_cfg.get("api.expose_internal_errors", False))
    except Exception:
        expose = False
    body: Dict[str, Any] = {
        "success": False,
        "error": "Internal server error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if expose:
        body["detail"] = str(exc)
    return JSONResponse(status_code=500, content=body)


# ─── CLI runner ───────────────────────────────────────────────────────────────

def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Run the API server using uvicorn."""
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ransomware Detector API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, reload=args.reload)
