"""
honeypot_manager.py
===================
Honeypot File Monitoring Module.

Tu dong trien khai cac file mau (honeypot) tai cac vi tri chiến lược để phát hiện
ransomware qua hành vi trinh sát hoặc mã hóa.

Features:
  - Tự động tạo file mồi nhử với tên hấp dẫn
  - Giám sát tất cả sự kiện READ/WRITE/DELETE trên honeypot
  - Khi phát hiện truy cập bất thường → kích hoạt auto_responder
  - Registry persistence trong JSON
  - Ghi log chi tiết vao logs/honeypot_alerts.log

Usage:
    manager = HoneypotManager()
    files = manager.deploy("C:\\Users")
    manager.start_monitoring()

    # Hoặc tích hợp với RealTimeMonitor:
    manager = HoneypotManager(watchdog_callback=monitor_callback)
"""

import os
import time
import logging
import hashlib
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

ALERT_LOG_PATH = "logs/honeypot_alerts.log"
REGISTRY_PATH = "data/honeypot_registry.json"


# ─── Default Honeypot Configuration ──────────────────────────────────────────

# Honeypot file names are intentionally prefixed with a marker so a curious
# user cannot mistake them for genuine personal files. The marker also helps
# AV products skip scanning them (avoiding false positives on the decoys).
_HP_PREFIX = "_DECOY_"
DEFAULT_HONEYPOT_NAMES = [
    f"{_HP_PREFIX}passwords.xlsx",
    f"{_HP_PREFIX}backup.docx",
    f"{_HP_PREFIX}financial_report_2025.pdf",
    f"{_HP_PREFIX}company_secrets.txt",
    f"{_HP_PREFIX}wallet_keys.txt",
    f"{_HP_PREFIX}tax_returns_2024.pdf",
    f"{_HP_PREFIX}credentials.xlsx",
    f"{_HP_PREFIX}banking_info.xlsx",
    f"{_HP_PREFIX}private_keys.pem",
    f"{_HP_PREFIX}recovery_codes.txt",
]

# Default to a single isolated directory under the user's profile so we never
# pollute Desktop / Documents / Downloads unless the operator opts in.
DEFAULT_HONEYPOT_LOCATIONS = [
    os.path.join(os.path.expanduser("~"), ".ransomware_detector", "honeypots"),
]


# ─── Honeypot Content Templates ──────────────────────────────────────────────

INNOCUOUS_CONTENT = {
    ".txt": """IMPORTANT - CONFIDENTIAL
========================

DO NOT DISTRIBUTE

Document ID: {doc_id}
Created: {date}
Classification: Internal Use Only

This document contains sensitive information.
If you are not the intended recipient, please contact IT Security immediately.

[Document contains placeholder content for security monitoring purposes]
""",
    ".xlsx": """# Excel file placeholder
# This is a decoy file for honeypot detection
Document ID: {doc_id}
Date: {date}
Confidential: YES
""",
    ".pdf": """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources <<
/Font <<
/F1 5 0 R
>>
>>
>>
endobj
4 0 obj
<<
/Length 200
>>
stream
BT
/F1 12 Tf
50 700 Td
(CONFIDENTIAL DOCUMENT) Tj
0 -20 Td
(Internal Use Only) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000270 00000 n
0000000520 00000 n
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
597
%%EOF
""",
    ".docx": """# Word document placeholder
# Decoy file for security monitoring
Document ID: {doc_id}
""",
    ".pem": """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDH...
[PLACEHOLDER - DECOY FILE FOR SECURITY MONITORING]
-----END PRIVATE KEY-----
""",
}


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class HoneypotFile:
    """Thông tin về một file honeypot."""
    id: str
    name: str
    path: str
    extension: str
    created_at: str
    last_accessed: Optional[str] = None
    access_count: int = 0
    is_triggered: bool = False
    trigger_reason: Optional[str] = None
    trigger_pid: Optional[int] = None
    trigger_process: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def record_access(self, pid: Optional[int] = None,
                      process_name: Optional[str] = None,
                      event_type: str = "unknown"):
        """Ghi nhận một lần truy cập."""
        self.last_accessed = datetime.now().isoformat()
        self.access_count += 1

        logger.info(
            f"Honeypot accessed: {self.name} by PID={pid} "
            f"({process_name}) - {event_type}"
        )


@dataclass
class HoneypotAccessEvent:
    """Sự kiện truy cập honeypot."""
    timestamp: str
    honeypot_id: str
    honeypot_name: str
    honeypot_path: str
    event_type: str  # "read" | "write" | "delete" | "modify"
    pid: Optional[int] = None
    process_name: Optional[str] = None
    severity: str = "HIGH"  # HIGH | CRITICAL
    action_taken: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── HoneypotManager ──────────────────────────────────────────────────────────

class HoneypotManager:
    """
    Quản lý honeypot files cho ransomware detection.

    Features:
      - Deploy/remove honeypot files tự động
      - Giám sát truy cập thông qua watchdog
      - Kích hoạt auto_responder khi phát hiện
      - Registry persistence
      - Access history tracking
    """

    def __init__(
        self,
        watchdog_callback: Optional[Callable[[HoneypotAccessEvent], None]] = None,
        auto_responder_callback: Optional[Callable[[str, int, str], None]] = None,
        honeypot_names: Optional[List[str]] = None,
        honeypot_locations: Optional[List[str]] = None,
        alert_log_path: str = ALERT_LOG_PATH,
        registry_path: str = REGISTRY_PATH,
    ):
        self.honeypot_names = honeypot_names or DEFAULT_HONEYPOT_NAMES
        self.honeypot_locations = honeypot_locations or DEFAULT_HONEYPOT_LOCATIONS
        self.alert_log_path = alert_log_path
        self.registry_path = registry_path

        # Callbacks
        self._watchdog_callback = watchdog_callback
        self._auto_responder_callback = auto_responder_callback

        # State
        self._honeypots: Dict[str, HoneypotFile] = {}
        self._access_history: List[HoneypotAccessEvent] = []
        self._is_monitoring = False
        self._monitor_lock = threading.Lock()
        self._id_counter = 0

        # Logging setup
        os.makedirs(os.path.dirname(self.alert_log_path), exist_ok=True)

        # Load existing registry
        self._load_registry()

    # ─── Public API ─────────────────────────────────────────────────────────

    def deploy(self, target_directory: str,
               max_per_location: int = 3) -> List[HoneypotFile]:
        """
        Triển khai honeypot files trong thư mục và các vị trí con.

        Args:
            target_directory: Thư mục gốc để deploy (VD: "C:\\Users")
            max_per_location: Số honeypot tối đa mỗi vị trí

        Returns:
            Danh sach HoneypotFile đã deploy
        """
        deployed = []
        target_dir = os.path.abspath(target_directory)

        # Find all available locations.
        # ``honeypot_locations`` may contain either:
        #   - an absolute path (preferred — isolated decoy directory), or
        #   - a relative name like "Desktop" which is joined with target_dir
        #     for backwards compatibility.
        available_locations = []
        for loc_name in self.honeypot_locations:
            expanded = os.path.expanduser(loc_name)
            if os.path.isabs(expanded):
                loc_path = expanded
            else:
                loc_path = os.path.join(target_dir, expanded)
            os.makedirs(loc_path, exist_ok=True)
            if os.path.isdir(loc_path):
                available_locations.append((loc_name, loc_path))

        # Also add root of target directory
        if target_directory:
            available_locations.append(("Root", target_dir))

        # Deploy honeypots
        used_names = set()
        for loc_name, loc_path in available_locations:
            if len(deployed) >= max_per_location * len(self.honeypot_locations):
                break

            # Pick random names from the list
            import random
            names_to_use = random.sample(
                self.honeypot_names,
                min(max_per_location, len(self.honeypot_names))
            )

            for name in names_to_use:
                if name in used_names:
                    continue
                used_names.add(name)

                hp = self._create_honeypot(loc_path, name)
                if hp:
                    deployed.append(hp)

        self._save_registry()
        logger.info(f"Deployed {len(deployed)} honeypot files")
        return deployed

    def remove_all(self) -> int:
        """
        Xóa tất cả honeypot files đang active.

        Returns:
            Số file đã xóa
        """
        removed = 0
        for hp_id, hp in list(self._honeypots.items()):
            try:
                if os.path.isfile(hp.path):
                    os.remove(hp.path)
                    logger.info(f"Removed honeypot: {hp.path}")
                del self._honeypots[hp_id]
                removed += 1
            except Exception as e:
                logger.error(f"Failed to remove honeypot {hp.path}: {e}")

        self._save_registry()
        logger.info(f"Removed {removed} honeypot files")
        return removed

    def get_status(self) -> List[HoneypotFile]:
        """Tra ve danh sach tat ca honeypot hien tai."""
        return list(self._honeypots.values())

    def get_active_count(self) -> int:
        """Tra ve so honeypot dang active."""
        return len(self._honeypots)

    def get_triggered_count(self, hours: int = 24) -> int:
        """Tra ve so honeypot bi trigger trong N gio."""
        cutoff = datetime.now().timestamp() - (hours * 3600)
        count = 0
        for hp in self._honeypots.values():
            if hp.is_triggered and hp.last_accessed:
                try:
                    accessed_time = datetime.fromisoformat(hp.last_accessed).timestamp()
                    if accessed_time >= cutoff:
                        count += 1
                except Exception:
                    pass
        return count

    def get_access_history(self, limit: int = 100) -> List[HoneypotAccessEvent]:
        """Tra ve lich su truy cap (gan nhat truoc)."""
        return sorted(
            self._access_history,
            key=lambda x: x.timestamp,
            reverse=True
        )[:limit]

    def on_file_event(self, file_path: str, event_type: str,
                      pid: Optional[int] = None,
                      process_name: Optional[str] = None):
        """
        Callback khi co su kien tren file (goi tu RealTimeMonitor).

        Args:
            file_path: Duong dan file co su kien
            event_type: Loai su kien ("created", "modified", "deleted", "accessed")
            pid: Process ID (neu co)
            process_name: Ten process
        """
        # Normalize path
        file_path = os.path.abspath(file_path)

        # Check if this file is a honeypot
        hp = self._find_honeypot(file_path)
        if hp is None:
            return

        # Record access
        hp.record_access(pid=pid, process_name=process_name, event_type=event_type)

        # Create event record
        access_event = HoneypotAccessEvent(
            timestamp=datetime.now().isoformat(),
            honeypot_id=hp.id,
            honeypot_name=hp.name,
            honeypot_path=hp.path,
            event_type=event_type,
            pid=pid,
            process_name=process_name,
            severity="CRITICAL" if event_type in ("deleted", "modified") else "HIGH",
        )

        # Check for suspicious patterns
        if event_type in ("modified", "deleted") or hp.access_count >= 3:
            access_event.severity = "CRITICAL"
            hp.is_triggered = True
            hp.trigger_reason = f"Multiple access ({hp.access_count}) or destructive event"
            hp.trigger_pid = pid
            hp.trigger_process = process_name

            # Take action
            action_taken = self._take_action(hp, access_event)
            access_event.action_taken = action_taken

        # Log alert
        self._log_alert(access_event)

        # Add to history
        self._access_history.append(access_event)

        # Keep history bounded
        if len(self._access_history) > 1000:
            self._access_history = self._access_history[-500:]

        # Callback to external handler
        if self._watchdog_callback:
            try:
                self._watchdog_callback(access_event)
            except Exception as e:
                logger.error(f"Watchdog callback error: {e}")

        # Save registry
        self._save_registry()

    def is_honeypot(self, file_path: str) -> bool:
        """Kiem tra xem file co phai la honeypot khong."""
        return self._find_honeypot(file_path) is not None

    def get_honeypot(self, file_path: str) -> Optional[HoneypotFile]:
        """Lay HoneypotFile neu la honeypot, nguoc lai None."""
        return self._find_honeypot(file_path)

    # ─── Private Methods ────────────────────────────────────────────────────

    def _create_honeypot(self, directory: str, name: str) -> Optional[HoneypotFile]:
        """Tao mot honeypot file trong directory."""
        file_path = os.path.join(directory, name)
        ext = os.path.splitext(name)[1].lower()

        # Avoid duplicates
        if os.path.isfile(file_path):
            logger.debug(f"Honeypot already exists: {file_path}")
            # Register existing file as honeypot
            hp = self._register_existing(file_path)
            return hp

        try:
            # Generate content
            content_template = INNOCUOUS_CONTENT.get(ext, INNOCUOUS_CONTENT[".txt"])
            content = content_template.format(
                doc_id=self._generate_doc_id(),
                date=datetime.now().strftime("%Y-%m-%d"),
            )

            # Write file
            os.makedirs(directory, exist_ok=True)
            with open(file_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(content)

            # Create HoneypotFile entry
            hp = HoneypotFile(
                id=self._generate_id(),
                name=name,
                path=file_path,
                extension=ext,
                created_at=datetime.now().isoformat(),
            )

            self._honeypots[hp.id] = hp
            logger.info(f"Created honeypot: {file_path}")
            return hp

        except Exception as e:
            logger.error(f"Failed to create honeypot {file_path}: {e}")
            return None

    def _register_existing(self, file_path: str) -> Optional[HoneypotFile]:
        """Dang ky mot file hien co lam honeypot."""
        ext = os.path.splitext(file_path)[1].lower()

        # Check if already registered
        for hp in self._honeypots.values():
            if os.path.normpath(hp.path) == os.path.normpath(file_path):
                return hp

        hp = HoneypotFile(
            id=self._generate_id(),
            name=os.path.basename(file_path),
            path=file_path,
            extension=ext,
            created_at=datetime.now().isoformat(),
        )

        self._honeypots[hp.id] = hp
        return hp

    def _find_honeypot(self, file_path: str) -> Optional[HoneypotFile]:
        """Tim honeypot bang duong dan (exact or parent match)."""
        abs_path = os.path.abspath(file_path)
        norm_path = os.path.normpath(abs_path)

        for hp in self._honeypots.values():
            hp_norm = os.path.normpath(hp.path)
            if hp_norm == norm_path:
                return hp
            # Also match if path ends with honeypot name
            if abs_path.endswith(hp.name) or norm_path.endswith(hp.name):
                return hp

        return None

    def _take_action(self, hp: HoneypotFile,
                     event: HoneypotAccessEvent) -> str:
        """Xu ly khi honeypot bi trigger."""
        action = f"Kill process PID={event.pid}"

        if self._auto_responder_callback:
            try:
                self._auto_responder_callback(
                    hp.path,
                    event.pid or -1,
                    event.process_name or "unknown"
                )
            except Exception as e:
                logger.error(f"Auto responder callback error: {e}")
                action = f"Action failed: {e}"

        return action

    def _log_alert(self, event: HoneypotAccessEvent):
        """Ghi alert vao log file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = (
            f"[{timestamp}] [{event.severity}] Honeypot triggered!\n"
            f"  File: {event.honeypot_path}\n"
            f"  Process: {event.process_name} (PID: {event.pid})\n"
            f"  Event: {event.event_type}\n"
            f"  Action: {event.action_taken or 'None'}\n"
            f"  ---\n"
        )

        try:
            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception as e:
            logger.error(f"Failed to write honeypot alert log: {e}")

    def _load_registry(self):
        """Load registry tu disk."""
        from core.security_utils import safe_read_json
        registry_file = self._resolve_path(self.registry_path)
        if not os.path.isfile(registry_file):
            return

        try:
            data = safe_read_json(registry_file, default=None)
            if data is None:
                return

            # Clean up non-existent files
            for hp_data in data.get("honeypots", []):
                try:
                    hp = HoneypotFile(**hp_data)
                    if os.path.isfile(hp.path):
                        self._honeypots[hp.id] = hp
                    else:
                        # File was deleted, check if it was triggered
                        if hp.is_triggered:
                            self._honeypots[hp.id] = hp
                except Exception:
                    continue

            logger.info(f"Loaded {len(self._honeypots)} honeypots from registry")

        except Exception as e:
            logger.warning(f"Failed to load honeypot registry: {e}")

    def _save_registry(self):
        """Save registry ra disk (atomic, crash-safe)."""
        from core.security_utils import atomic_write_json
        registry_file = self._resolve_path(self.registry_path)
        data = {
            "version": "1.0",
            "last_updated": datetime.now().isoformat(),
            "honeypots": [hp.to_dict() for hp in self._honeypots.values()],
        }
        if not atomic_write_json(registry_file, data):
            logger.warning("Failed to save honeypot registry")

    def _generate_id(self) -> str:
        """Sinh unique ID."""
        self._id_counter += 1
        return f"HP_{datetime.now().strftime('%Y%m%d')}_{self._id_counter:04d}"

    @staticmethod
    def _generate_doc_id() -> str:
        """Sinh document ID ngau nhien."""
        import random
        return f"DOC-{random.randint(10000, 99999)}-{hashlib.md5(str(time.time()).encode()).hexdigest()[:6].upper()}"

    def _resolve_path(self, path: str) -> str:
        """Resolve relative path tu project root."""
        if os.path.isabs(path):
            return path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, path)


# ─── Singleton ────────────────────────────────────────────────────────────────

_honeypot_manager: Optional[HoneypotManager] = None


def get_honeypot_manager() -> HoneypotManager:
    """Lay singleton HoneypotManager."""
    global _honeypot_manager
    if _honeypot_manager is None:
        _honeypot_manager = HoneypotManager()
    return _honeypot_manager
