"""
api/schemas.py
=============
Pydantic models cho Ransomware Detector REST API.

Cung cap request/response schemas cho tất cả endpoints.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from pydantic import BaseModel, Field, ConfigDict


# ─── Enums ─────────────────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanMode(str, Enum):
    FULL = "full"
    QUICK = "quick"
    INCREMENTAL = "incremental"


class SensitivityProfile(str, Enum):
    BALANCED = "balanced"
    HIGH_SENSITIVITY = "high_sensitivity"
    PARANOID = "paranoid"


class FeedbackType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


class UserRole(str, Enum):
    ADMIN = "admin"
    READER = "reader"


# ─── Auth Schemas ─────────────────────────────────────────────────────────────

class TokenRequest(BaseModel):
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.READER


class UserResponse(BaseModel):
    username: str
    role: str
    disabled: bool = False


class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    role: UserRole = UserRole.READER


class APIKeyResponse(BaseModel):
    key: str
    name: str
    role: str
    created_at: str


# ─── Scan Schemas ─────────────────────────────────────────────────────────────

class ScanFileRequest(BaseModel):
    scan_mode: ScanMode = ScanMode.FULL
    sensitivity: SensitivityProfile = SensitivityProfile.BALANCED
    recursive: bool = True


class ScanResultItem(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    path: str
    filename: str
    size: int
    extension: str
    threat_level: str
    probability: float
    risk_level: str
    entropy: Optional[float] = None
    scan_time_ms: float
    error: Optional[str] = None
    yara_matches: List[Dict[str, str]] = Field(default_factory=list)
    yara_boosted: bool = False
    # v3.0: VirusTotal
    sha256: Optional[str] = ""
    vt_available: bool = False
    vt_malicious_count: int = 0
    vt_suspicious_count: int = 0
    vt_total_engines: int = 0
    vt_detection_ratio: str = "0/0"
    vt_permalink: str = ""
    vt_from_cache: bool = False
    vt_error: str = ""
    vt_pending: bool = False


class ScanFileResponse(BaseModel):
    scan_id: str
    started_at: str
    completed_at: Optional[str] = None
    total_files: int
    scanned_files: int
    threats_found: int
    results: List[Dict[str, Any]]
    summary: Dict[str, Any]


class ScanHashRequest(BaseModel):
    sha256: str = Field(..., min_length=64, max_length=64)
    include_detections: bool = True


class ScanHashResponse(BaseModel):
    sha256: str
    file_report: Optional[Dict[str, Any]] = None
    cached: bool = False
    from_cache: bool = False
    error: Optional[str] = None


# ─── Office Scanner Schemas ───────────────────────────────────────────────────

class OfficeScanResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    file_path: str
    filename: str
    extension: str
    file_size: int
    sha256: str
    threat_level: str
    triggers_found: List[str] = Field(default_factory=list)
    macro_code_snippet: str = ""
    macro_count: int = 0
    is_macro_enabled: bool = False
    pdf_actions: List[Dict[str, Any]] = Field(default_factory=list)
    pdf_javascript: List[str] = Field(default_factory=list)
    rtf_objects: List[Dict[str, Any]] = Field(default_factory=list)
    yara_matches: List[Dict[str, str]] = Field(default_factory=list)
    analysis_time_ms: float = 0.0
    error: Optional[str] = None
    recommendation: str = ""


class OfficeScanResponse(BaseModel):
    total_files: int
    threats_found: int
    malicious_count: int
    suspicious_count: int
    clean_count: int
    results: List[Dict[str, Any]]


# ─── Status Schemas ───────────────────────────────────────────────────────────

class MonitorStatus(BaseModel):
    is_running: bool
    watch_directory: Optional[str] = None
    total_analyzed: int = 0
    total_threats: int = 0
    queue_size: int = 0
    uptime_seconds: float = 0.0


class SystemStatus(BaseModel):
    version: str = "2.0.0"
    monitor: MonitorStatus
    ml_model_loaded: bool
    ml_threshold: float
    yara_engine_type: str
    yara_rules_count: int
    entropy_monitoring: Dict[str, Any]
    honeypot_count: int = 0


class SystemHealth(BaseModel):
    status: str  # "healthy" | "degraded" | "down"
    components: Dict[str, str]
    timestamp: str


# ─── Alert Schemas ─────────────────────────────────────────────────────────────

class AlertItem(BaseModel):
    timestamp: str
    event_type: str
    path: str
    filename: str
    probability: float
    risk_level: str
    entropy: Optional[float] = None
    source: str = "scanner"  # "scanner" | "monitor" | "honeypot" | "entropy"


class AlertListResponse(BaseModel):
    total: int
    alerts: List[AlertItem]
    page: int = 1
    page_size: int = 50


# ─── Honeypot Schemas ──────────────────────────────────────────────────────────

class HoneypotDeployRequest(BaseModel):
    target_directory: str = Field(..., description="Directory to deploy honeypots")
    max_per_location: int = Field(default=3, ge=1, le=10)


class HoneypotFileResponse(BaseModel):
    id: str
    name: str
    path: str
    extension: str
    created_at: str
    last_accessed: Optional[str] = None
    access_count: int = 0
    is_triggered: bool = False


class HoneypotDeployResponse(BaseModel):
    deployed_count: int
    honeypots: List[HoneypotFileResponse]


class HoneypotStatusResponse(BaseModel):
    active_count: int
    triggered_24h: int
    honeypots: List[HoneypotFileResponse]


class HoneypotAccessEventResponse(BaseModel):
    timestamp: str
    honeypot_id: str
    honeypot_name: str
    honeypot_path: str
    event_type: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    severity: str
    action_taken: Optional[str] = None


# ─── ML Feedback Schemas ───────────────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    sha256: str
    predicted_label: str
    feedback_label: str
    feedback_type: FeedbackType
    features_b64: Optional[str] = None
    user_id: Optional[str] = None


class FeedbackResponse(BaseModel):
    success: bool
    feedback_id: str
    total_feedback_samples: int


class RetrainRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_name: Optional[str] = None


class RetrainResponse(BaseModel):
    success: bool
    new_model_version: str
    previous_accuracy: Optional[float] = None
    new_accuracy: Optional[float] = None
    samples_used: int
    training_time_seconds: float


class ModelVersionResponse(BaseModel):
    version: str
    created_at: str
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    sample_count: int
    is_active: bool = False


class MLStatsResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    total_samples: int
    false_positive_count: int
    false_negative_count: int
    last_retrain: Optional[str] = None
    active_model_version: str
    model_versions: List[ModelVersionResponse]


# ─── Report Schemas ────────────────────────────────────────────────────────────

class ReportGenerateRequest(BaseModel):
    format: str = Field(default="pdf", pattern="^(pdf|csv|json)$")
    include_details: bool = True
    scan_id: Optional[str] = None


class ReportResponse(BaseModel):
    report_id: str
    format: str
    created_at: str
    file_path: str
    download_url: str


# ─── Generic API Response ─────────────────────────────────────────────────────

class APIResponse(BaseModel):
    success: bool = True
    message: str = ""
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class PaginatedResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[Any]
