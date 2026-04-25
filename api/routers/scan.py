"""
api/routers/scan.py
==================
Scan endpoints for the Ransomware Detector API.
"""

import os
import threading
from datetime import datetime
from typing import List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form

from api.auth import get_current_user
from api.schemas import (
    ScanFileResponse, ScanHashRequest, ScanHashResponse,
    OfficeScanResponse,
)
from core.security_utils import (
    PathSafetyError,
    compute_sha256,
    resolve_safe_path,
)

# Office upload defence-in-depth
_OFFICE_ALLOWED_EXTENSIONS = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm",
    ".pdf", ".rtf",
}

router = APIRouter(prefix="/scan", tags=["Scan"])


# ─── Background scan state ──────────────────────────────────────────────────────

_scan_results_store: Dict[str, Dict[str, Any]] = {}
_scan_counter = 0
_scan_lock = threading.Lock()


def _next_scan_id() -> str:
    global _scan_counter
    with _scan_lock:
        _scan_counter += 1
        return f"scan_{_scan_counter:06d}"


def _collect_files(directory: str, recursive: bool) -> List[str]:
    """Collect files from directory."""
    files = []
    try:
        if recursive:
            for root, _, filenames in os.walk(directory):
                for fn in filenames:
                    files.append(os.path.join(root, fn))
        else:
            for fn in os.listdir(directory):
                path = os.path.join(directory, fn)
                if os.path.isfile(path):
                    files.append(path)
    except Exception:
        pass
    return files


# ─── POST /scan/file ────────────────────────────────────────────────────────────

@router.post("/file", response_model=ScanFileResponse)
async def scan_file(
    directory: str = Form(...),
    recursive: bool = Form(True),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Scan all files in a directory.

    Supports: PE, Office, PDF, and generic files.
    Returns threat analysis results.
    """
    scan_id = _next_scan_id()
    started_at = datetime.now().isoformat()

    # Path-traversal / SSRF defence: caller must pass a directory inside one of
    # the configured allowed roots. Empty allowlist = scan disabled.
    try:
        from core.config_manager import config as _cfg
        allowed_roots = _cfg.get("api.allowed_scan_roots", []) or []
    except Exception:
        allowed_roots = []
    if not allowed_roots:
        raise HTTPException(
            status_code=403,
            detail=(
                "Scanning is disabled: configure api.allowed_scan_roots in "
                "data/config.json with one or more absolute directories."
            ),
        )
    try:
        safe_dir = resolve_safe_path(directory, allowed_roots)
    except PathSafetyError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    if not safe_dir.is_dir():
        raise HTTPException(status_code=400, detail=f"Directory not found: {safe_dir}")
    directory = str(safe_dir)

    # Collect files
    files = _collect_files(directory, recursive)

    if not files:
        return ScanFileResponse(
            scan_id=scan_id,
            started_at=started_at,
            completed_at=datetime.now().isoformat(),
            total_files=0,
            scanned_files=0,
            threats_found=0,
            results=[],
            summary={"clean": 0, "suspicious": 0, "malicious": 0, "errors": 0},
        )

    # Import core modules
    try:
        from core.ml_engine import get_engine
        from core.yara_engine import get_yara_engine
        from core.feature_extractor import extract_features
        from core.fp_reducer import apply_fp_reduction
        from core.config_manager import config
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Core module error: {e}")

    results = []
    threats_found = 0
    engine = get_engine()
    yara_engine = get_yara_engine()

    # VirusTotal settings from config
    vt_enabled        = config.get("virustotal.enabled", False)
    vt_api_key        = config.get("virustotal.api_key", "")
    vt_auto_check     = config.get("virustotal.auto_check", False)
    vt_mal_threshold  = 5

    vt_client = None
    if vt_enabled and vt_api_key and len(vt_api_key) > 10:
        try:
            from core.virustotal_client import get_vt_client
            vt_client = get_vt_client(vt_api_key)
        except Exception:
            vt_client = None

    def _query_vt(file_path: str, sha256: str) -> dict:
        """Query VT, return dict of VT fields. Returns empty dict on failure."""
        if vt_client is None or not vt_client.is_configured():
            return {}
        report = vt_client.get_file_report(sha256)
        if report is None:
            return {}
        return {
            "vt_available":          True,
            "vt_malicious_count":    report.malicious_count,
            "vt_suspicious_count":   report.suspicious_count,
            "vt_total_engines":      report.total_engines,
            "vt_detection_ratio":    report.detection_ratio,
            "vt_permalink":          report.permalink,
            "vt_from_cache":         bool(report.cached_at),
            "vt_error":              "",
        }

    for file_path in files:
        try:
            size = os.path.getsize(file_path)

            # Compute SHA256 for VT lookup (streaming — supports multi-GB files)
            sha256 = compute_sha256(file_path)

            features = extract_features(file_path)

            if features is None:
                results.append({
                    "path": file_path,
                    "filename": os.path.basename(file_path),
                    "size": size,
                    "extension": os.path.splitext(file_path)[1].lower(),
                    "threat_level": "UNKNOWN",
                    "probability": 0.0,
                    "risk_level": "UNKNOWN",
                    "entropy": 0.0,
                    "scan_time_ms": 0.0,
                    "error": "Feature extraction failed",
                    "yara_matches": [],
                    "yara_boosted": False,
                    "sha256": sha256,
                    "vt_available": False,
                    "vt_malicious_count": 0,
                    "vt_suspicious_count": 0,
                    "vt_total_engines": 0,
                    "vt_detection_ratio": "0/0",
                    "vt_permalink": "",
                    "vt_from_cache": False,
                    "vt_error": "",
                    "vt_pending": False,
                })
                continue

            label, proba = engine.predict(features)

            # YARA scan
            yara_matches = []
            yara_boosted = False
            if yara_engine:
                try:
                    matches = yara_engine.scan_file(file_path)
                    if matches:
                        yara_boosted = True
                        for m in matches:
                            yara_matches.append(m.to_dict())
                        proba, _ = yara_engine.apply_yara_boost(proba, matches)
                except Exception:
                    pass

            # FP reduction
            proba_adjusted, effective_thresh, fp_reason = apply_fp_reduction(
                file_path, proba, engine.get_threshold()
            )
            final_risk = engine.get_risk_level(proba_adjusted)

            entry = {
                "path": file_path,
                "filename": os.path.basename(file_path),
                "size": size,
                "extension": os.path.splitext(file_path)[1].lower(),
                "threat_level": final_risk,
                "probability": round(proba_adjusted, 4),
                "risk_level": final_risk,
                "entropy": round(float(features[0]), 4),
                "scan_time_ms": 0.0,
                "error": None,
                "yara_matches": yara_matches,
                "yara_boosted": yara_boosted,
                "fp_reason": fp_reason,
                "sha256": sha256,
                "vt_available": False,
                "vt_malicious_count": 0,
                "vt_suspicious_count": 0,
                "vt_total_engines": 0,
                "vt_detection_ratio": "0/0",
                "vt_permalink": "",
                "vt_from_cache": False,
                "vt_error": "",
                "vt_pending": False,
            }

            # VirusTotal lookup (v3.0)
            should_vt = vt_auto_check or final_risk in ("HIGH", "CRITICAL")
            if should_vt and vt_client:
                entry["vt_pending"] = True
                vt_fields = _query_vt(file_path, sha256)
                entry.update(vt_fields)
                entry["vt_pending"] = False

                # Override risk level dựa trên VT result
                if entry.get("vt_malicious_count", 0) >= vt_mal_threshold:
                    entry["threat_level"] = "CRITICAL"
                    entry["risk_level"]   = "CRITICAL"
                    entry["fp_reason"]   += f" | VT({entry['vt_malicious_count']}/{entry['vt_total_engines']})"
                elif entry.get("vt_malicious_count", 0) >= 1:
                    entry["threat_level"] = "HIGH"
                    entry["risk_level"]   = "HIGH"
                    entry["fp_reason"]   += f" | VT_suspicious({entry['vt_malicious_count']}/{entry['vt_total_engines']})"

            results.append(entry)

            if final_risk in ("HIGH", "CRITICAL"):
                threats_found += 1

        except Exception as e:
            results.append({
                "path": file_path,
                "filename": os.path.basename(file_path),
                "size": 0,
                "extension": os.path.splitext(file_path)[1].lower(),
                "threat_level": "ERROR",
                "probability": 0.0,
                "risk_level": "UNKNOWN",
                "entropy": 0.0,
                "scan_time_ms": 0.0,
                "error": str(e),
                "yara_matches": [],
                "yara_boosted": False,
                "sha256": "",
                "vt_available": False,
                "vt_malicious_count": 0,
                "vt_suspicious_count": 0,
                "vt_total_engines": 0,
                "vt_detection_ratio": "0/0",
                "vt_permalink": "",
                "vt_from_cache": False,
                "vt_error": "",
                "vt_pending": False,
            })

    # Summary
    summary = {
        "clean": sum(1 for r in results if r["risk_level"] == "SAFE"),
        "suspicious": sum(1 for r in results if r["risk_level"] in ("LOW", "MEDIUM")),
        "malicious": sum(1 for r in results if r["risk_level"] in ("HIGH", "CRITICAL")),
        "errors": sum(1 for r in results if r.get("error")),
    }

    # Store results
    _scan_results_store[scan_id] = {
        "results": results,
        "summary": summary,
        "directory": directory,
    }

    return ScanFileResponse(
        scan_id=scan_id,
        started_at=started_at,
        completed_at=datetime.now().isoformat(),
        total_files=len(files),
        scanned_files=len(results),
        threats_found=threats_found,
        results=results,
        summary=summary,
    )


# ─── POST /scan/hash ───────────────────────────────────────────────────────────

@router.post("/hash", response_model=ScanHashResponse)
async def scan_hash(
    request: ScanHashRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Query VirusTotal for a file by SHA256 hash.

    Uses cache to avoid duplicate API calls.
    """
    sha256 = request.sha256.strip().lower()

    if len(sha256) != 64:
        raise HTTPException(status_code=400, detail="Invalid SHA256 hash")

    try:
        from core.virustotal_client import get_vt_client
    except ImportError:
        raise HTTPException(status_code=500, detail="VirusTotal client not available")

    vt = get_vt_client()

    if not vt.is_configured():
        raise HTTPException(
            status_code=503,
            detail="VirusTotal API not configured. Set api_key in settings."
        )

    report = vt.get_file_report(sha256)

    if report is None:
        return ScanHashResponse(
            sha256=sha256,
            file_report=None,
            cached=False,
            from_cache=False,
            error="File not found in VirusTotal database",
        )

    return ScanHashResponse(
        sha256=sha256,
        file_report=report.to_dict(),
        cached=bool(report.cached_at),
        from_cache=bool(report.cached_at),
        error=None,
    )


# ─── POST /scan/office ─────────────────────────────────────────────────────────

@router.post("/office", response_model=OfficeScanResponse)
async def scan_office(
    files: List[UploadFile] = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Scan uploaded Office documents for malware.

    Supports: .doc, .docx, .docm, .xls, .xlsx, .xlsm, .ppt, .pptx, .pdf, .rtf
    """
    try:
        from core.office_doc_analyzer import OfficeDocAnalyzer
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Office analyzer not available: {e}")

    analyzer = OfficeDocAnalyzer()
    results = []
    malicious_count = 0
    suspicious_count = 0
    clean_count = 0

    import tempfile
    import shutil

    temp_dir = tempfile.mkdtemp()

    try:
        # Read upload limit from config (default 50 MiB)
        try:
            from core.config_manager import config as _cfg
            max_upload_bytes = int(_cfg.get("api.max_upload_mb", 50)) * 1024 * 1024
        except Exception:
            max_upload_bytes = 50 * 1024 * 1024

        # Save uploaded files temporarily — enforce extension allowlist + size cap
        saved_paths = []
        for upload_file in files:
            if not upload_file.filename:
                continue
            # Strip directory components (defence against path traversal in filename)
            safe_name = os.path.basename(upload_file.filename)
            ext = os.path.splitext(safe_name)[1].lower()
            if ext not in _OFFICE_ALLOWED_EXTENSIONS:
                raise HTTPException(
                    status_code=415,
                    detail=f"Unsupported file type: {ext or '(none)'}",
                )
            save_path = os.path.join(temp_dir, safe_name)
            written = 0
            with open(save_path, "wb") as f:
                while True:
                    chunk = upload_file.file.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_upload_bytes:
                        f.close()
                        os.unlink(save_path)
                        raise HTTPException(
                            status_code=413,
                            detail=f"File {safe_name} exceeds {max_upload_bytes // (1024 * 1024)} MiB limit",
                        )
                    f.write(chunk)
            saved_paths.append(save_path)

        # Analyze each file
        for file_path in saved_paths:
            result = analyzer.analyze(file_path)
            results.append(result.to_dict())

            if result.threat_level == "MALICIOUS":
                malicious_count += 1
            elif result.threat_level == "SUSPICIOUS":
                suspicious_count += 1
            else:
                clean_count += 1

    finally:
        # Cleanup temp files
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

    return OfficeScanResponse(
        total_files=len(results),
        threats_found=malicious_count + suspicious_count,
        malicious_count=malicious_count,
        suspicious_count=suspicious_count,
        clean_count=clean_count,
        results=results,
    )
