"""
rule_updater.py
==============
Task 3: YARA Rule Pack Auto-Updater.

Fetches community YARA rules from remote sources, validates them,
and manages updates with scheduling support.

Usage:
    updater = YARARuleUpdater()
    updater.fetch_and_validate(url)
    updater.start_scheduler()
"""

import os
import hashlib
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, List, Optional, Any

import hmac
from core.security_utils import atomic_write_json, safe_read_json

logger = logging.getLogger(__name__)


def _hash_eq(a: str, b: str) -> bool:
    """Constant-time, case-insensitive comparison of hex digests."""
    return hmac.compare_digest(a.lower().strip(), b.lower().strip())


class YARARuleUpdater:
    """
    YARA Rule Pack Auto-Updater.
    Downloads community YARA rules from remote sources and manages updates.
    """

    # Each source MAY include ``sha256`` — if present the downloaded payload
    # MUST match exactly. This defends against upstream-account-compromise
    # (poisoned rules with ``condition: false`` would silently disable
    # detection). Operators pin the hash by computing it once after manual
    # review and updating ``data/config.json[yara.sources]``.
    SOURCES = [
        {
            "name": "Yara-Rules/rules",
            "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Ransomware.yar",
            "enabled": False,  # disabled by default until a SHA is pinned
            "sha256": "",
        },
        {
            "name": "Neo23x0/signature-base",
            "url": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_ransomware.yar",
            "enabled": False,
            "sha256": "",
        },
    ]

    RULES_DIR = "rules/community/"
    UPDATE_LOG = "rules/update_log.json"
    CHECK_INTERVAL = 86400  # 24 hours in seconds

    # Built-in rules that should never be overwritten
    BUILTIN_RULES = {"ransomware_core.yar", "yara_rules.yar", "ransomware_signatures.yar"}

    def __init__(self):
        self._scheduler_timer: Optional[threading.Timer] = None
        self._running = False

    def fetch_and_validate(self, url: str, expected_sha256: str = "") -> bool:
        """
        Download rule from URL, optionally verify SHA256, compile, save if valid.

        Args:
            url: URL to fetch YARA rule from
            expected_sha256: hex digest the payload MUST match. Empty disables
                the check (legacy behaviour) but logs a warning.

        Returns:
            True if successful, False otherwise
        """
        if not url.lower().startswith("https://"):
            logger.error("Refusing to fetch YARA rule over non-HTTPS URL: %s", url)
            return False
        logger.info(f"Fetching YARA rules from: {url}")

        try:
            # Download rules — cap to 16 MiB to avoid memory bombs.
            response = urllib.request.urlopen(url, timeout=30)
            raw = response.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                logger.error("YARA payload exceeded 16 MiB cap: %s", url)
                return False
            rule_content = raw.decode("utf-8")

            if not rule_content.strip():
                logger.warning(f"Empty rule content from: {url}")
                return False

            # Pin verification
            actual_sha = hashlib.sha256(raw).hexdigest()
            if expected_sha256:
                if not _hash_eq(actual_sha, expected_sha256):
                    logger.error(
                        "SHA256 mismatch for %s (expected=%s, got=%s) — refusing",
                        url, expected_sha256, actual_sha,
                    )
                    self._log_update(url, "", "sha256_mismatch",
                                     error=f"expected {expected_sha256}, got {actual_sha}")
                    return False
            else:
                logger.warning(
                    "No expected_sha256 pinned for %s; downloaded SHA=%s. "
                    "Pin this hash in config to harden against upstream compromise.",
                    url, actual_sha,
                )

            # Try to compile with YARA
            if self._compile_rules(rule_content):
                # Save to file
                filename = self._get_filename_from_url(url)
                filepath = os.path.join(self.RULES_DIR, filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)

                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(rule_content)

                logger.info(f"Successfully saved rule: {filepath}")
                self._log_update(url, filename, "success", rules_count=self._count_rules(rule_content))
                return True
            else:
                logger.warning(f"Rule compilation failed for: {url}")
                self._log_update(url, "", "compilation_failed")
                return False

        except urllib.error.URLError as e:
            logger.error(f"Network error fetching rule from {url}: {e}")
            self._log_update(url, "", "network_error", error=str(e))
            return False
        except Exception as e:
            logger.error(f"Error processing rule from {url}: {e}")
            self._log_update(url, "", "error", error=str(e))
            return False

    def _compile_rules(self, rule_content: str) -> bool:
        """
        Try to compile rule content with YARA.

        Args:
            rule_content: YARA rule content

        Returns:
            True if compilation successful, False otherwise
        """
        try:
            import yara  # type: ignore[import-not-found]
            yara.compile(source=rule_content)
            return True
        except ImportError:
            # yara-python not available - skip compilation
            logger.warning("yara-python not available - skipping compilation validation")
            return True
        except Exception as e:
            logger.warning(f"YARA compilation failed: {e}")
            return False

    def _count_rules(self, rule_content: str) -> int:
        """Count number of rules in content."""
        return rule_content.count("rule ")

    def _get_filename_from_url(self, url: str) -> str:
        """Extract filename from URL."""
        filename = url.split("/")[-1]
        if not filename.endswith(".yar"):
            filename += ".yar"
        return filename

    def _log_update(
        self,
        source: str,
        filename: str,
        status: str,
        rules_count: int = 0,
        error: Optional[str] = None
    ):
        """Log update to update_log.json."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "filename": filename,
            "status": status,
            "rules_count": rules_count,
        }
        if error:
            log_entry["error"] = error

        # Load existing log (best-effort)
        logs = safe_read_json(self.UPDATE_LOG, default=[])
        if not isinstance(logs, list):
            logs = []

        logs.append(log_entry)

        # Keep only last 100 entries
        logs = logs[-100:]

        # Atomic save
        atomic_write_json(self.UPDATE_LOG, logs)

    def get_update_log(self) -> List[Dict[str, Any]]:
        """Get update log entries."""
        data = safe_read_json(self.UPDATE_LOG, default=[])
        return data if isinstance(data, list) else []

    def check_for_updates(self) -> Dict[str, Any]:
        """
        Check all enabled sources for updates.

        Returns:
            Dictionary with update status
        """
        results = {
            "total_sources": 0,
            "successful": 0,
            "failed": 0,
            "details": [],
        }

        for source in self.SOURCES:
            if not source.get("enabled", True):
                continue

            results["total_sources"] += 1
            success = self.fetch_and_validate(
                source["url"], expected_sha256=source.get("sha256", ""),
            )

            results["details"].append({
                "name": source["name"],
                "url": source["url"],
                "success": success,
            })

            if success:
                results["successful"] += 1
            else:
                results["failed"] += 1

        return results

    def start_scheduler(self):
        """Start periodic update check using threading.Timer."""
        if self._running:
            logger.warning("Scheduler already running")
            return

        self._running = True

        def periodic_check():
            if self._running:
                self.check_for_updates()
                # Schedule next check
                self._scheduler_timer = threading.Timer(
                    self.CHECK_INTERVAL,
                    periodic_check
                )
                self._scheduler_timer.daemon = True
                self._scheduler_timer.start()

        # Start first check after interval
        self._scheduler_timer = threading.Timer(
            self.CHECK_INTERVAL,
            periodic_check
        )
        self._scheduler_timer.daemon = True
        self._scheduler_timer.start()

        logger.info(f"YARA rule auto-updater started (interval: {self.CHECK_INTERVAL}s)")

    def stop_scheduler(self):
        """Stop periodic update check."""
        self._running = False
        if self._scheduler_timer:
            self._scheduler_timer.cancel()
            self._scheduler_timer = None
        logger.info("YARA rule auto-updater stopped")

    def resolve_conflict(self, rule_name: str, new_content: str) -> bool:
        """
        Resolve conflict when same rule exists in multiple sources.

        Args:
            rule_name: Name of the conflicting rule
            new_content: New rule content

        Returns:
            True if new content should be used, False to keep existing
        """
        # Check if it's a built-in rule
        if rule_name in self.BUILTIN_RULES:
            logger.info(f"Keeping built-in rule: {rule_name}")
            return False

        # Compare hashes - keep newer
        existing_path = os.path.join(self.RULES_DIR, rule_name)
        if not os.path.exists(existing_path):
            return True

        try:
            with open(existing_path, "r") as f:
                existing_content = f.read()

            existing_hash = hashlib.md5(existing_content.encode()).hexdigest()
            new_hash = hashlib.md5(new_content.encode()).hexdigest()

            if new_hash != existing_hash:
                logger.info(f"Rule {rule_name} has newer version")
                return True
            else:
                logger.info(f"Rule {rule_name} is identical")
                return False

        except Exception as e:
            logger.error(f"Error resolving conflict for {rule_name}: {e}")
            return False

    def get_local_rules(self) -> List[Dict[str, Any]]:
        """
        Get list of locally installed rules.

        Returns:
            List of rule info dictionaries
        """
        rules = []

        if not os.path.exists(self.RULES_DIR):
            return rules

        for filename in os.listdir(self.RULES_DIR):
            if not filename.endswith(".yar"):
                continue

            filepath = os.path.join(self.RULES_DIR, filename)
            try:
                stat = os.stat(filepath)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                rules.append({
                    "name": filename,
                    "path": filepath,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "rules_count": self._count_rules(content),
                    "is_builtin": filename in self.BUILTIN_RULES,
                })
            except Exception as e:
                logger.warning(f"Error reading rule {filename}: {e}")

        return rules

    def force_update_now(self) -> Dict[str, Any]:
        """
        Force immediate update check.

        Returns:
            Update results dictionary
        """
        return self.check_for_updates()

    def get_source_status(self) -> List[Dict[str, Any]]:
        """Get status of all configured sources."""
        status = []
        for source in self.SOURCES:
            status.append({
                "name": source["name"],
                "url": source["url"],
                "enabled": source.get("enabled", True),
            })
        return status


# Singleton instance
_updater: Optional[YARARuleUpdater] = None


def get_rule_updater() -> YARARuleUpdater:
    """Get singleton YARARuleUpdater instance."""
    global _updater
    if _updater is None:
        _updater = YARARuleUpdater()
    return _updater
