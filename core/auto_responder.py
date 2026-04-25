"""
auto_responder.py
=================
Task 5: Auto-Response Actions (v2.3).

Provides automated response capabilities for detected threats:
  - Quarantine files
  - Restore quarantined files
  - Kill malicious processes
  - Block network traffic via Windows Firewall

Usage:
    responder = AutoResponder()
    result = responder.quarantine_file("C:\\path\\to\\malware.exe")
"""

import os
import sys
import shutil
import logging
import subprocess
import threading
from datetime import datetime
from typing import TYPE_CHECKING, Dict, Any, Optional

from core.security_utils import atomic_write_json, compute_sha256, safe_read_json

if TYPE_CHECKING:
    import psutil
    PSUTIL_AVAILABLE = True
else:
    try:
        import psutil
        PSUTIL_AVAILABLE = True
    except ImportError:  # pragma: no cover
        psutil = None
        PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class AutoResponder:
    """
    Auto-Response Actions for ransomware detection.
    Handles quarantine, process termination, and network blocking.
    """

    QUARANTINE_DIR = "quarantine/"
    AUDIT_LOG = "logs/response_audit.log"
    MANIFEST_FILE = "quarantine/quarantine_manifest.json"

    SYSTEM_PROCESSES = [
        "svchost.exe", "lsass.exe", "csrss.exe",
        "wininit.exe", "services.exe", "smss.exe",
        "winlogon.exe", "dwm.exe", "explorer.exe",
        "taskmgr.exe", "cmd.exe", "powershell.exe",
    ]

    RESPONSE_POLICY = {
        "CRITICAL": "auto_quarantine",  # automatic with countdown (see DEFAULT_COUNTDOWN_S)
        "HIGH": "ask_user",              # show dialog with countdown
        "MEDIUM": "notify_only",
        "LOW": "log_only",
    }

    # Number of seconds to wait before auto-quarantining a CRITICAL detection
    # so a UI / operator has a chance to abort. Configurable via
    # ``auto_response.countdown_seconds`` in data/config.json.
    DEFAULT_COUNTDOWN_S = 30

    # Disk-quota safety: refuse to quarantine when the destination volume has
    # less than this fraction of free space. A 100 GiB ransomware drop must
    # never be allowed to fill the disk and crash the OS. Audit P3-15.
    MIN_FREE_DISK_FRACTION = 0.10  # require >=10% free
    MIN_FREE_DISK_BYTES    = 1 * 1024 * 1024 * 1024  # and >=1 GiB absolute

    def __init__(self):
        """Initialize AutoResponder."""
        os.makedirs(self.QUARANTINE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(self.AUDIT_LOG), exist_ok=True)
        self._abort_callback: Optional[Any] = None  # callable(file_path) -> bool
        # Serialise audit-log writes so concurrent quarantines from a thread
        # pool cannot interleave half-flushed lines (audit P3-15).
        self._audit_lock = threading.Lock()

    def set_abort_callback(self, callback) -> None:
        """
        Register a callback invoked during the countdown before auto-quarantine.

        The callback receives the file path and must return ``True`` to abort
        (do not quarantine) or ``False`` to allow the action. If no callback
        is registered the action proceeds after the countdown elapses.
        """
        self._abort_callback = callback

    def quarantine_with_countdown(self, file_path: str, *,
                                   reason: str = "Auto-detected CRITICAL",
                                   seconds: Optional[int] = None) -> Dict[str, Any]:
        """
        Wait ``seconds`` (default from config or DEFAULT_COUNTDOWN_S) before
        quarantining ``file_path``. Returns the same dict as
        :meth:`quarantine_file` plus an ``aborted`` flag.

        This is the preferred entry point for CRITICAL events because it
        gives the user a chance to undo a false-positive quarantine.
        """
        import time as _time
        try:
            from core.config_manager import config as _cfg
            cfg_seconds = int(_cfg.get("auto_response.countdown_seconds", self.DEFAULT_COUNTDOWN_S))
        except Exception:
            cfg_seconds = self.DEFAULT_COUNTDOWN_S
        wait_s = seconds if seconds is not None else cfg_seconds
        wait_s = max(0, wait_s)

        deadline = _time.monotonic() + wait_s
        while _time.monotonic() < deadline:
            if self._abort_callback is not None:
                try:
                    if bool(self._abort_callback(file_path)):
                        self._log_action("QUARANTINE_ABORTED", file=file_path, reason=reason)
                        logger.info("Quarantine aborted by callback for %s", file_path)
                        return {"success": False, "aborted": True, "id": None}
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("abort_callback raised: %s", exc)
            # Poll once per second so the abort signal is responsive without
            # spinning a CPU.
            _time.sleep(min(1.0, max(0.0, deadline - _time.monotonic())))

        result = self.quarantine_file(file_path, reason=reason)
        result["aborted"] = False
        return result

    def quarantine_file(self, file_path: str, reason: str = "Auto-detected threat") -> Dict[str, Any]:
        """
        Quarantine a malicious file.

        The move is performed defensively to avoid data loss even when
        ``file_path`` and the quarantine directory are on different volumes
        (where ``shutil.move`` falls back to copy-and-delete with no rollback):

          1. SHA256 of source is computed up-front.
          2. File is copied to ``<quarantine>/<file>.quarantined``.
          3. The destination is ``fsync()``-ed so the write reaches disk.
          4. SHA256 of destination is recomputed and compared with #1.
          5. Only on match is the source removed (with retries to defeat
             transient AV / handle-locking races).
          6. On any failure we delete the partial destination and bail out
             — the original file is preserved.

        Args:
            file_path: Path to the file to quarantine
            reason: Reason for quarantine

        Returns:
            Dictionary with quarantine details
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found for quarantine: {file_path}")
            return {"success": False, "error": "File not found"}

        # Disk-quota guard — refuse before we copy anything. This is a
        # critical safety net: a 100 GB ransomware payload must NOT be
        # allowed to fill the system volume.
        quota_err = self._check_disk_quota(file_path)
        if quota_err is not None:
            logger.error("Refusing to quarantine %s: %s", file_path, quota_err)
            self._log_action(
                "QUARANTINE_REFUSED", file=file_path, reason=quota_err,
            )
            return {"success": False, "error": quota_err}

        # Generate unique quarantine ID
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_id = f"Q_{timestamp}"

        # Create quarantine subdirectory
        quarantine_subdir = os.path.join(self.QUARANTINE_DIR, timestamp)
        os.makedirs(quarantine_subdir, exist_ok=True)

        # Compute hash of *source* (streaming — supports multi-GB files).
        # This anchors the integrity check that follows the copy.
        source_hash = compute_sha256(file_path)
        if not source_hash:
            logger.error("Cannot compute SHA256 of source: %s", file_path)
            return {"success": False, "error": "Source unreadable"}

        # New path
        filename = os.path.basename(file_path)
        new_filename = f"{filename}.quarantined"
        new_path = os.path.join(quarantine_subdir, new_filename)

        try:
            self._safe_quarantine_move(file_path, new_path, source_hash)

            # Create manifest entry
            manifest_entry = {
                "id": quarantine_id,
                "original_path": file_path,
                "quarantined_path": new_path,
                "hash": source_hash,
                "timestamp": datetime.now().isoformat(),
                "reason": reason,
                "size": os.path.getsize(new_path),
            }

            # Update manifest
            manifest = self._load_manifest()
            manifest[quarantine_id] = manifest_entry
            self._save_manifest(manifest)

            # Log to audit
            self._log_action("QUARANTINE", file=file_path, hash=source_hash, reason=reason)

            logger.info(f"File quarantined: {file_path} -> {new_path}")
            return {"success": True, "id": quarantine_id, "new_path": new_path}

        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")
            # Best-effort cleanup of any partial destination so we do not
            # leave a half-copied artefact behind.
            try:
                if os.path.isfile(new_path):
                    os.remove(new_path)
            except OSError:
                pass
            return {"success": False, "error": str(e)}

    @staticmethod
    def _safe_quarantine_move(src: str, dst: str, expected_hash: str,
                              *, delete_retries: int = 5,
                              delete_retry_delay_s: float = 0.2) -> None:
        """Copy *src* → *dst* with fsync + SHA256 verify, then delete *src*.

        Raises on any inconsistency — caller must clean up *dst* on error.
        """
        # 1. Copy with metadata preservation (timestamps useful for forensics).
        shutil.copy2(src, dst)

        # 2. fsync the destination so the bytes survive a power loss before
        #    the source is deleted. fsync of the directory is best-effort
        #    (not all filesystems / Windows builds support it).
        try:
            with open(dst, "rb", buffering=0) as f_dst:
                os.fsync(f_dst.fileno())
        except OSError as exc:
            logger.debug("fsync(dst) failed (continuing): %s", exc)

        # 3. Verify destination matches the source hash.
        dst_hash = compute_sha256(dst)
        if not dst_hash or dst_hash.lower() != expected_hash.lower():
            raise IOError(
                f"Quarantine integrity check failed: src={expected_hash} "
                f"dst={dst_hash}"
            )

        # 4. Delete source with retries — on Windows AV scanners frequently
        #    hold transient handles right after we close the source.
        last_exc: Optional[Exception] = None
        for attempt in range(delete_retries):
            try:
                os.remove(src)
                return
            except (OSError, PermissionError) as exc:
                last_exc = exc
                if attempt + 1 < delete_retries:
                    import time as _t
                    _t.sleep(delete_retry_delay_s)
        raise IOError(
            f"Could not delete source after copy ({delete_retries} attempts): {last_exc}"
        )

    def restore_file(self, quarantine_id: str) -> bool:
        """
        Restore a quarantined file.

        Args:
            quarantine_id: Quarantine ID

        Returns:
            True if successful, False otherwise
        """
        manifest = self._load_manifest()
        entry = manifest.get(quarantine_id)

        if not entry:
            logger.error(f"Quarantine ID not found: {quarantine_id}")
            return False

        original_path = entry["original_path"]
        quarantined_path = entry["quarantined_path"]

        if not os.path.exists(quarantined_path):
            logger.error(f"Quarantined file not found: {quarantined_path}")
            return False

        # Verify the quarantined file matches what we recorded — guards
        # against silent tamper between quarantine and restore.
        recorded_hash = entry.get("hash")
        if recorded_hash:
            current_hash = compute_sha256(quarantined_path)
            if not current_hash or current_hash.lower() != str(recorded_hash).lower():
                logger.error(
                    "Refusing to restore — quarantined file hash changed "
                    "(expected=%s, got=%s)", recorded_hash, current_hash,
                )
                self._log_action(
                    "RESTORE_REJECTED",
                    file=original_path, quarantine_id=quarantine_id,
                    reason="hash_mismatch",
                )
                return False

        try:
            # Ensure original directory exists
            os.makedirs(os.path.dirname(original_path) or ".", exist_ok=True)

            # Same defensive move (copy → fsync → verify → delete) as
            # the outbound quarantine path.
            self._safe_quarantine_move(
                quarantined_path, original_path,
                recorded_hash or compute_sha256(quarantined_path),
            )

            # Remove from manifest
            del manifest[quarantine_id]
            self._save_manifest(manifest)

            # Log to audit
            self._log_action("RESTORE", file=original_path, quarantine_id=quarantine_id)

            logger.info(f"File restored: {original_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore file: {e}")
            return False

    def delete_quarantined_file(self, quarantine_id: str) -> bool:
        """Permanently delete a quarantined file and remove it from manifest."""
        manifest = self._load_manifest()
        entry = manifest.get(quarantine_id)

        if not entry:
            logger.error(f"Quarantine ID not found for deletion: {quarantine_id}")
            return False

        quarantined_path = entry["quarantined_path"]

        try:
            if os.path.exists(quarantined_path):
                os.remove(quarantined_path)

            del manifest[quarantine_id]
            self._save_manifest(manifest)

            self._log_action("DELETE_QUARANTINE", file=entry["original_path"], quarantine_id=quarantine_id)
            logger.info(f"Quarantined file permanently deleted: {quarantined_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete quarantined file: {e}")
            return False

    def kill_process(self, pid: int, process_name: str = "") -> bool:
        """
        Kill a malicious process.

        Args:
            pid: Process ID to kill
            process_name: Process name for logging

        Returns:
            True if successful, False otherwise
        """
        # Check if it's a system process
        if process_name.lower() in [p.lower() for p in self.SYSTEM_PROCESSES]:
            logger.warning(f"Cannot kill system process: {process_name}")
            return False

        if not PSUTIL_AVAILABLE:
            return self._kill_process_windows(pid)

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()

            # Double-check system processes
            if proc_name.lower() in [p.lower() for p in self.SYSTEM_PROCESSES]:
                logger.warning(f"Cannot kill system process: {proc_name}")
                return False

            # Kill the process
            proc.kill()

            # Log to audit
            self._log_action("KILL_PROCESS", pid=pid, name=proc_name)

            logger.info(f"Process killed: PID={pid}, Name={proc_name}")
            return True

        except psutil.NoSuchProcess:
            logger.warning(f"Process not found: PID={pid}")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied killing process: PID={pid}")
            return False
        except Exception as e:
            logger.error(f"Failed to kill process: {e}")
            return False

    def _kill_process_windows(self, pid: int) -> bool:
        """Kill process using Windows taskkill."""
        if sys.platform != "win32":
            return False

        try:
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._log_action("KILL_PROCESS", pid=pid)
                return True
            else:
                logger.error(f"Failed to kill process: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Failed to kill process: {e}")
            return False

    def block_network(self, pid: int, process_name: str = "") -> bool:
        """
        Block network traffic for a process using Windows Firewall.

        Args:
            pid: Process ID
            process_name: Process name

        Returns:
            True if successful, False otherwise
        """
        if sys.platform != "win32":
            logger.warning("Network blocking only supported on Windows")
            return False

        # Sanitize process name to prevent command injection
        safe_process_name = self._sanitize_process_name(process_name)
        
        # Create firewall rule name with sanitized name
        rule_name = f"RansomwareDetector_Block_{pid}_{safe_process_name}"

        try:
            # Get process path
            if PSUTIL_AVAILABLE:
                try:
                    proc = psutil.Process(pid)
                    process_path = proc.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    logger.debug(f"Cannot get process path: {e}")
                    process_path = ""
            else:
                process_path = ""

            # Create outbound block rule
            if process_path:
                # Sanitize path for command
                safe_path = self._sanitize_path(process_path)
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out",
                    "action=block",
                    f"program={safe_path}",
                    "enable=yes"
                ]
            else:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out",
                    "action=block",
                    "remoteport=*",
                    "enable=yes",
                    f"description=Blocked by Ransomware Detector PID={pid}"
                ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self._log_action("BLOCK_NETWORK", pid=pid, name=safe_process_name)
                logger.info(f"Network blocked for PID={pid}: {rule_name}")
                return True
            else:
                logger.error(f"Failed to block network: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Network blocking command timed out")
            return False
        except Exception as e:
            logger.error(f"Failed to block network: {e}")
            return False

    def _sanitize_process_name(self, process_name: str) -> str:
        """
        Sanitize process name to prevent command injection.
        Removes or replaces characters that could be used for command injection.
        """
        if not process_name:
            return "unknown"
        
        # Remove characters that could be used for command injection
        # Allow only alphanumeric, dots, dashes, underscores
        import re
        sanitized = re.sub(r'[^\w.\-]', '_', process_name)
        
        # Limit length
        sanitized = sanitized[:50]
        
        # Ensure not empty
        return sanitized if sanitized else "unknown"

    def _sanitize_path(self, path: str) -> str:
        """
        Sanitize file path for use in command.
        Returns the path unchanged if valid, otherwise empty string.
        """
        if not path:
            return ""
        
        # Validate path is absolute and exists
        if not os.path.isabs(path):
            logger.warning(f"Refusing to block with relative path: {path}")
            return ""
        
        # Check for suspicious patterns
        suspicious = [";", "&", "|", "`", "$", "(", ")", "{", "}", "[", "]", "<", ">"]
        if any(c in path for c in suspicious):
            logger.warning(f"Refusing to block with suspicious path: {path}")
            return ""
        
        return path

    def unblock_network(self, pid: int, process_name: str = "") -> bool:
        """
        Unblock network traffic for a process.

        Args:
            pid: Process ID
            process_name: Process name

        Returns:
            True if successful, False otherwise
        """
        if sys.platform != "win32":
            return False

        # Sanitize must mirror block_network() exactly so the rule name
        # produced here matches the one created at block-time. Without this,
        # netsh would silently fail to find the rule and orphaned firewall
        # rules accumulate (DoS by exhaustion).
        safe_process_name = self._sanitize_process_name(process_name)
        rule_name = f"RansomwareDetector_Block_{pid}_{safe_process_name}"

        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=" + rule_name
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self._log_action("UNBLOCK_NETWORK", pid=pid, name=safe_process_name)
                logger.info(f"Network unblocked for PID={pid}")
                return True
            else:
                return False

        except Exception as e:
            logger.error(f"Failed to unblock network: {e}")
            return False

    def get_response_action(self, severity: str) -> str:
        """
        Get the response action for a given severity level.

        Args:
            severity: One of "CRITICAL", "HIGH", "MEDIUM", "LOW"

        Returns:
            Response action string
        """
        return self.RESPONSE_POLICY.get(severity.upper(), "log_only")

    def should_auto_respond(self, severity: str) -> bool:
        """Check if action should be automatic based on severity."""
        action = self.get_response_action(severity)
        return action == "auto_quarantine"

    def _load_manifest(self) -> Dict[str, Any]:
        """Load quarantine manifest."""
        data = safe_read_json(self.MANIFEST_FILE, default={})
        return data if isinstance(data, dict) else {}

    def _save_manifest(self, manifest: Dict[str, Any]):
        """Save quarantine manifest atomically (crash-safe)."""
        if not atomic_write_json(self.MANIFEST_FILE, manifest):
            logger.error("Failed to persist quarantine manifest")

    def _log_action(self, action: str, **kwargs):
        """Log action to audit log.

        Writes are serialised through ``self._audit_lock`` so concurrent
        quarantine operations from the scanner thread pool cannot interleave
        partially-flushed lines (which would corrupt audit reconstruction).
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parts = [f"[{timestamp}] {action}"]

        for key, value in kwargs.items():
            parts.append(f"{key}={value}")

        log_line = " | ".join(parts) + "\n"

        try:
            with self._audit_lock:
                # Open / append / close inside the lock so the OS-level
                # write is fully flushed before another thread proceeds.
                with open(self.AUDIT_LOG, "a", encoding="utf-8") as f:
                    f.write(log_line)
                    f.flush()
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def _check_disk_quota(self, file_path: str) -> Optional[str]:
        """Return an error string if the quarantine volume is too full.

        Computes (a) free fraction and (b) absolute free bytes on the volume
        backing :pyattr:`QUARANTINE_DIR` and refuses any quarantine that
        would land on a near-full disk. This prevents a 100 GB ransomware
        drop from filling the system drive and crashing the host
        (audit P3-15).

        Returns ``None`` when the quarantine is allowed to proceed.
        """
        try:
            usage = shutil.disk_usage(self.QUARANTINE_DIR)
        except OSError as exc:
            # If we cannot stat the volume something is very wrong — refuse.
            return f"disk_usage failed: {exc}"

        free_fraction = usage.free / max(usage.total, 1)
        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            file_size = 0

        # Need enough headroom for the file plus the absolute floor.
        required_bytes = max(self.MIN_FREE_DISK_BYTES, file_size * 2)
        if usage.free < required_bytes or free_fraction < self.MIN_FREE_DISK_FRACTION:
            return (
                f"insufficient disk space: free={usage.free} bytes "
                f"({free_fraction*100:.1f}%), required>={required_bytes} bytes "
                f"and >={self.MIN_FREE_DISK_FRACTION*100:.0f}% free"
            )
        return None

    def get_quarantine_list(self) -> list:
        """Get list of quarantined files."""
        manifest = self._load_manifest()
        return [
            {
                "id": qid,
                "original_path": entry["original_path"],
                "reason": entry["reason"],
                "timestamp": entry["timestamp"],
            }
            for qid, entry in manifest.items()
        ]

    def set_response_policy(self, severity: str, action: str):
        """
        Set response policy for a severity level.

        Args:
            severity: One of "CRITICAL", "HIGH", "MEDIUM", "LOW"
            action: One of "auto_quarantine", "ask_user", "notify_only", "log_only"
        """
        valid_actions = ["auto_quarantine", "ask_user", "notify_only", "log_only"]
        if action not in valid_actions:
            logger.error(f"Invalid action: {action}")
            return

        self.RESPONSE_POLICY[severity.upper()] = action
        logger.info(f"Response policy updated: {severity} -> {action}")


# Singleton instance
_responder: Optional[AutoResponder] = None


def get_auto_responder() -> AutoResponder:
    """Get singleton AutoResponder instance."""
    global _responder
    if _responder is None:
        _responder = AutoResponder()
    return _responder
