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
import logging
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm

# ─── Add project root to path ──────────────────────────────────────────────────

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ─── Logging ─────────────────────────────────────────────────────────────────

logger = logging.getLogger("api.main")

# ─── API Routers ──────────────────────────────────────────────────────────────

from starlette import status as http_status
from api.routers import scan, status as status_router, honeypots, reports
from api.auth import (
    authenticate_user, create_access_token, get_current_user, require_admin,
)
from api.schemas import (
    TokenResponse,
    APIKeyCreate,
    APIKeyResponse,
)


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

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router, prefix="/api/v1")
app.include_router(status_router.router, prefix="/api/v1")
app.include_router(honeypots.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


# ─── Auth Endpoints ──────────────────────────────────────────────────────────

@app.post("/api/v1/auth/token", response_model=TokenResponse, tags=["Auth"])
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    Authenticate with username/password and get JWT access token.
    """
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

    Requires admin role.
    """
    import secrets

    key = secrets.token_urlsafe(32)

    return APIKeyResponse(
        key=key,
        name=request.name,
        role=request.role.value,
        created_at=datetime.now().isoformat(),
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
async def global_exception_handler(request, exc):
    """Catch-all exception handler."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return {
        "success": False,
        "error": str(exc),
        "timestamp": datetime.now().isoformat(),
    }


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
