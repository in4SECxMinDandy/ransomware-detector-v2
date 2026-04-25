"""
api/routers/status.py
===================
Status and alerts endpoints.
"""

from datetime import datetime
from typing import List, Dict, Any

from fastapi import APIRouter, Depends, Query

from api.auth import get_current_user
from api.schemas import (
    SystemStatus, MonitorStatus, AlertListResponse, AlertItem,
    SystemHealth,
)

router = APIRouter(prefix="", tags=["Status"])


# ─── In-memory alert store (shared with monitor callbacks) ────────────────────

_alert_store: List[Dict[str, Any]] = []
_alert_lock = __import__("threading").Lock()


def add_alert(alert: Dict[str, Any]):
    """Add an alert to the store (called by monitor callbacks)."""
    with _alert_lock:
        _alert_store.append(alert)
        # Keep only last 1000
        if len(_alert_store) > 1000:
            _alert_store[:] = _alert_store[-1000:]


def get_alerts(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Get recent alerts."""
    with _alert_lock:
        sorted_alerts = sorted(_alert_store, key=lambda x: x.get("timestamp", ""), reverse=True)
        return sorted_alerts[offset:offset + limit]


# ─── GET /status ────────────────────────────────────────────────────────────────

@router.get("/status", response_model=SystemStatus)
async def get_status(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get system status including monitor state, ML model info, and entropy stats.
    """
    try:
        from core.ml_engine import get_engine
        from core.yara_engine import get_yara_engine
        from core.honeypot_manager import get_honeypot_manager
    except ImportError:
        return SystemStatus(
            version="2.0.0",
            monitor=MonitorStatus(is_running=False, total_analyzed=0, total_threats=0),
            ml_model_loaded=False,
            ml_threshold=0.65,
            yara_engine_type="unavailable",
            yara_rules_count=0,
            entropy_monitoring={},
            honeypot_count=0,
        )

    # Monitor status
    try:
        # Try to get the singleton monitor
        # (In practice, this would be injected at app startup)
        monitor_stats = {
            "is_running": False,
            "total_analyzed": 0,
            "total_threats": 0,
            "queue_size": 0,
        }
        entropy_stats = {
            "enabled": True,
            "threshold": 7.5,
            "consecutive_files": 5,
            "recent_entries": 0,
        }
    except Exception:
        monitor_stats = {"is_running": False, "total_analyzed": 0, "total_threats": 0, "queue_size": 0}
        entropy_stats = {"enabled": False}

    # ML Engine
    engine = get_engine()
    ml_loaded = engine.is_loaded() if hasattr(engine, "is_loaded") else False
    ml_threshold = engine.get_threshold() if hasattr(engine, "get_threshold") else 0.65

    # YARA
    yara_engine = get_yara_engine()
    yara_type = yara_engine.get_engine_type() if yara_engine else "unavailable"
    yara_count = yara_engine.get_rules_count() if yara_engine else 0

    # Honeypot
    try:
        hp_manager = get_honeypot_manager()
        hp_count = hp_manager.get_active_count()
    except Exception:
        hp_count = 0

    return SystemStatus(
        version="2.0.0",
        monitor=MonitorStatus(
            is_running=monitor_stats.get("is_running", False),
            total_analyzed=monitor_stats.get("total_analyzed", 0),
            total_threats=monitor_stats.get("total_threats", 0),
            queue_size=monitor_stats.get("queue_size", 0),
        ),
        ml_model_loaded=ml_loaded,
        ml_threshold=ml_threshold,
        yara_engine_type=yara_type,
        yara_rules_count=yara_count,
        entropy_monitoring=entropy_stats,
        honeypot_count=hp_count,
    )


# ─── GET /alerts ───────────────────────────────────────────────────────────────

@router.get("/alerts", response_model=AlertListResponse)
async def get_alerts_endpoint(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get recent alerts with pagination.
    """
    offset = (page - 1) * page_size
    alerts = get_alerts(limit=page_size, offset=offset)

    items = [
        AlertItem(
            timestamp=a.get("timestamp", ""),
            event_type=a.get("event_type", "unknown"),
            path=a.get("path", ""),
            filename=a.get("filename", ""),
            probability=a.get("probability", 0.0),
            risk_level=a.get("risk_level", "UNKNOWN"),
            entropy=a.get("entropy"),
            source=a.get("source", "scanner"),
        )
        for a in alerts
    ]

    with _alert_lock:
        total = len(_alert_store)

    return AlertListResponse(
        total=total,
        alerts=items,
        page=page,
        page_size=page_size,
    )


# ─── GET /health ────────────────────────────────────────────────────────────────

@router.get("/health", response_model=SystemHealth)
async def get_health(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Simple health check endpoint.
    """
    components = {}
    overall = "healthy"

    # Check core modules
    try:
        from core.ml_engine import get_engine
        engine = get_engine()
        if engine.is_loaded() if hasattr(engine, "is_loaded") else False:
            components["ml_engine"] = "ok"
        else:
            components["ml_engine"] = "not_loaded"
            overall = "degraded"
    except Exception as e:
        components["ml_engine"] = f"error: {e}"
        overall = "degraded"

    try:
        from core.yara_engine import get_yara_engine
        yara = get_yara_engine()
        if yara:
            components["yara_engine"] = "ok"
        else:
            components["yara_engine"] = "unavailable"
    except Exception as e:
        components["yara_engine"] = f"error: {e}"

    return SystemHealth(
        status=overall,
        components=components,
        timestamp=datetime.now().isoformat(),
    )
