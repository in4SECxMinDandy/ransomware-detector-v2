"""
api/routers/honeypots.py
=====================
Honeypot management endpoints.
"""

from typing import List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException

from api.auth import get_current_user, require_admin
from api.schemas import (
    HoneypotDeployRequest, HoneypotDeployResponse, HoneypotFileResponse,
    HoneypotStatusResponse, HoneypotAccessEventResponse,
)

router = APIRouter(prefix="/honeypots", tags=["Honeypots"])


# ─── GET /honeypots ────────────────────────────────────────────────────────────

@router.get("", response_model=HoneypotStatusResponse)
async def get_honeypots(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get status of all active honeypot files.
    """
    try:
        from core.honeypot_manager import get_honeypot_manager
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Honeypot module not available: {e}")

    manager = get_honeypot_manager()

    honeypots = manager.get_status()
    triggered_24h = manager.get_triggered_count(hours=24)

    items = [
        HoneypotFileResponse(
            id=hp.id,
            name=hp.name,
            path=hp.path,
            extension=hp.extension,
            created_at=hp.created_at,
            last_accessed=hp.last_accessed,
            access_count=hp.access_count,
            is_triggered=hp.is_triggered,
        )
        for hp in honeypots
    ]

    return HoneypotStatusResponse(
        active_count=len(honeypots),
        triggered_24h=triggered_24h,
        honeypots=items,
    )


# ─── POST /honeypots/deploy ────────────────────────────────────────────────────

@router.post("/deploy", response_model=HoneypotDeployResponse)
async def deploy_honeypots(
    request: HoneypotDeployRequest,
    current_user: Dict[str, Any] = Depends(require_admin),
):
    """
    Deploy honeypot files to a target directory.

    Requires admin role.
    """
    try:
        from core.honeypot_manager import get_honeypot_manager
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Honeypot module not available: {e}")

    import os
    if not os.path.isdir(request.target_directory):
        raise HTTPException(status_code=400, detail=f"Directory not found: {request.target_directory}")

    manager = get_honeypot_manager()

    deployed = manager.deploy(
        request.target_directory,
        max_per_location=request.max_per_location,
    )

    items = [
        HoneypotFileResponse(
            id=hp.id,
            name=hp.name,
            path=hp.path,
            extension=hp.extension,
            created_at=hp.created_at,
        )
        for hp in deployed
    ]

    return HoneypotDeployResponse(
        deployed_count=len(deployed),
        honeypots=items,
    )


# ─── DELETE /honeypots ────────────────────────────────────────────────────────

@router.delete("")
async def remove_all_honeypots(
    current_user: Dict[str, Any] = Depends(require_admin),
):
    """
    Remove all active honeypot files.

    Requires admin role.
    """
    try:
        from core.honeypot_manager import get_honeypot_manager
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Honeypot module not available: {e}")

    manager = get_honeypot_manager()
    removed = manager.remove_all()

    return {"success": True, "removed_count": removed}


# ─── GET /honeypots/history ───────────────────────────────────────────────────

@router.get("/history", response_model=List[HoneypotAccessEventResponse])
async def get_honeypot_history(
    limit: int = 100,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Get honeypot access history.
    """
    try:
        from core.honeypot_manager import get_honeypot_manager
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Honeypot module not available: {e}")

    manager = get_honeypot_manager()
    history = manager.get_access_history(limit=limit)

    return [
        HoneypotAccessEventResponse(
            timestamp=event.timestamp,
            honeypot_id=event.honeypot_id,
            honeypot_name=event.honeypot_name,
            honeypot_path=event.honeypot_path,
            event_type=event.event_type,
            pid=event.pid,
            process_name=event.process_name,
            severity=event.severity,
            action_taken=event.action_taken,
        )
        for event in history
    ]
