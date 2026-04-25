"""
api/routers/reports.py
====================
Report generation and download endpoints.
"""

import os
import re
import uuid
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from api.auth import get_current_user
from api.schemas import ReportGenerateRequest, ReportResponse
from core.security_utils import PathSafetyError, resolve_safe_path

# Allow only formats we actually generate. Anything else is rejected before
# touching the filesystem so format= cannot be abused as a path component.
_ALLOWED_FORMATS = {"pdf", "csv", "json"}

# report_id is generated server-side as ``report_<8-hex>`` (see
# generate_report below) so we only ever need to accept that exact shape on
# download. Reject anything else outright — defends against path traversal
# (``../``), absolute paths, NUL bytes, UNC injection, etc.
_REPORT_ID_RE = re.compile(r"^report_[0-9a-f]{8}$")

router = APIRouter(prefix="/reports", tags=["Reports"])


# ─── Report storage ─────────────────────────────────────────────────────────────

_REPORT_DIR = "reports"
os.makedirs(_REPORT_DIR, exist_ok=True)


# ─── POST /reports/generate ────────────────────────────────────────────────────

@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    request: ReportGenerateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Generate a threat report in PDF, CSV, or JSON format.
    """
    report_id = f"report_{uuid.uuid4().hex[:8]}"
    timestamp = datetime.now().isoformat()

    if request.format == "pdf":
        filename = f"{report_id}.pdf"
        file_path = os.path.join(_REPORT_DIR, filename)
        # Generate PDF
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib.units import inch

            c = canvas.Canvas(file_path, pagesize=letter)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(1 * inch, 10.5 * inch, "Ransomware Detector v2 — Threat Report")
            c.setFont("Helvetica", 10)
            c.drawString(1 * inch, 10 * inch, f"Report ID: {report_id}")
            c.drawString(1 * inch, 9.7 * inch, f"Generated: {timestamp}")
            c.drawString(1 * inch, 9.4 * inch, f"Format: {request.format.upper()}")
            c.drawString(1 * inch, 9.1 * inch, f"User: {current_user.get('username', current_user.get('name', 'unknown'))}")
            c.showPage()
            c.save()
        except ImportError:
            raise HTTPException(status_code=500, detail="PDF generation requires reportlab")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    elif request.format == "csv":
        filename = f"{report_id}.csv"
        file_path = os.path.join(_REPORT_DIR, filename)
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("report_id,timestamp,format,user\n")
                f.write(f"{report_id},{timestamp},{request.format},{current_user.get('username', 'unknown')}\n")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"CSV generation failed: {e}")

    elif request.format == "json":
        filename = f"{report_id}.json"
        file_path = os.path.join(_REPORT_DIR, filename)
        try:
            import json
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump({
                    "report_id": report_id,
                    "timestamp": timestamp,
                    "format": request.format,
                    "user": current_user.get("username", current_user.get("name", "unknown")),
                    "version": "2.0.0",
                }, f, indent=2)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"JSON generation failed: {e}")

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}")

    return ReportResponse(
        report_id=report_id,
        format=request.format,
        created_at=timestamp,
        file_path=file_path,
        download_url=f"/reports/{report_id}/download",
    )


# ─── GET /reports/{report_id}/download ────────────────────────────────────────

@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    format: str = "pdf",
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Download a previously generated report.

    Security: ``report_id`` and ``format`` are both *user-controlled*. We
    validate them against strict allowlists before constructing any path,
    then run :func:`resolve_safe_path` as a defence-in-depth check that
    confirms the resolved file lives under ``_REPORT_DIR`` (so symlinks or
    OS-level path tricks cannot escape the report directory either).
    """
    fmt = format.lower()
    if fmt not in _ALLOWED_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported report format")
    if not _REPORT_ID_RE.match(report_id):
        # Use 404 rather than 400 to avoid leaking which IDs exist.
        raise HTTPException(status_code=404, detail="Report not found")

    filename = f"{report_id}.{fmt}"
    candidate = os.path.join(_REPORT_DIR, filename)

    try:
        safe_path = resolve_safe_path(candidate, [_REPORT_DIR])
    except PathSafetyError:
        # Path resolution escaped the reports/ root — treat as not-found
        # rather than disclosing the safety failure.
        raise HTTPException(status_code=404, detail="Report not found")

    if not safe_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "json": "application/json",
    }[fmt]

    return FileResponse(
        path=str(safe_path),
        filename=filename,
        media_type=media_type,
    )
