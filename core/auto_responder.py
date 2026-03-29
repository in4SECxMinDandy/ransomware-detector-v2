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
import json
import shutil
import logging
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
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
        "CRITICAL": "auto_quarantine",  # automatic, no prompt
        "HIGH": "ask_user",              # show dialog with countdown
        "MEDIUM": "notify_only",
        "LOW": "log_only",
    }

    def __init__(self):
        """Initialize AutoResponder."""
        os.makedirs(self.QUARANTINE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(self.AUDIT_LOG), exist_ok=True)

    def quarantine_file(self, file_path: str, reason: str = "Auto-detected threat") -> Dict[str, Any]:
        """
        Quarantine a malicious file.

        Args:
            file_path: Path to the file to quarantine
            reason: Reason for quarantine

        Returns:
            Dictionary with quarantine details
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found for quarantine: {file_path}")
            return {"success": False, "error": "File not found"}

        # Generate unique quarantine ID
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_id = f"Q_{timestamp}"

        # Create quarantine subdirectory
        quarantine_subdir = os.path.join(self.QUARANTINE_DIR, timestamp)
        os.makedirs(quarantine_subdir, exist_ok=True)

        # Compute hash
        import hashlib
        file_hash = None
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        except IOError as e:
            logger.error(f"Failed to read file for hash: {e}")
            file_hash = None

        # New path
        filename = os.path.basename(file_path)
        new_filename = f"{filename}.quarantined"
        new_path = os.path.join(quarantine_subdir, new_filename)

        try:
            # Move file to quarantine
            shutil.move(file_path, new_path)

            # Create manifest entry
            manifest_entry = {
                "id": quarantine_id,
                "original_path": file_path,
                "quarantined_path": new_path,
                "hash": file_hash,
                "timestamp": datetime.now().isoformat(),
                "reason": reason,
                "size": os.path.getsize(new_path),
            }

            # Update manifest
            manifest = self._load_manifest()
            manifest[quarantine_id] = manifest_entry
            self._save_manifest(manifest)

            # Log to audit
            self._log_action("QUARANTINE", file=file_path, hash=file_hash, reason=reason)

            logger.info(f"File quarantined: {file_path} -> {new_path}")
            return {"success": True, "id": quarantine_id, "new_path": new_path}

        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")
            return {"success": False, "error": str(e)}

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

        try:
            # Ensure original directory exists
            os.makedirs(os.path.dirname(original_path), exist_ok=True)

            # Move back to original location
            shutil.move(quarantined_path, original_path)

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

        rule_name = f"RansomwareDetector_Block_{pid}_{process_name}"

        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=" + rule_name
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self._log_action("UNBLOCK_NETWORK", pid=pid, name=process_name)
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
        if not os.path.exists(self.MANIFEST_FILE):
            return {}
        try:
            with open(self.MANIFEST_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load manifest: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error loading manifest: {e}")
            return {}

    def _save_manifest(self, manifest: Dict[str, Any]):
        """Save quarantine manifest."""
        os.makedirs(os.path.dirname(self.MANIFEST_FILE), exist_ok=True)
        with open(self.MANIFEST_FILE, "w") as f:
            json.dump(manifest, f, indent=2)

    def _log_action(self, action: str, **kwargs):
        """Log action to audit log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parts = [f"[{timestamp}] {action}"]

        for key, value in kwargs.items():
            parts.append(f"{key}={value}")

        log_line = " | ".join(parts) + "\n"

        try:
            with open(self.AUDIT_LOG, "a") as f:
                f.write(log_line)
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

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
