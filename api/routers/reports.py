"""
api/routers/reports.py
====================
Report generation and download endpoints.
"""

import os
import uuid
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from api.auth import get_current_user
from api.schemas import ReportGenerateRequest, ReportResponse

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
    """
    filename = f"{report_id}.{format}"
    file_path = os.path.join(_REPORT_DIR, filename)

    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "json": "application/json",
    }.get(format, "application/octet-stream")

    return FileResponse(
        path=file_path,
        filename=filename,
        media_type=media_type,
    )
