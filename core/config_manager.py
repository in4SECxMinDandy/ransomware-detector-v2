"""
config_manager.py
=================
Centralized configuration management for Ransomware Detector.

All hardcoded values across the codebase are extracted here.
Supports dot-notation access, JSON persistence, and runtime updates.

Usage:
    from core.config_manager import config

    # Read value
    threshold = config.get("ml.default_threshold")

    # Update value
    config.set("ml.default_threshold", 0.75)

    # Reset to defaults
    config.reset_to_defaults()
"""

import os
import json
import copy
import logging
from typing import Any, Optional, Dict
from threading import Lock

logger = logging.getLogger(__name__)


# ─── Default Configuration ───────────────────────────────────────────────────

DEFAULT_CONFIG: Dict[str, Any] = {
    "ml": {
        "default_threshold":   0.65,
        "min_threshold":       0.30,
        "max_threshold":       0.95,
        "target_precision":    0.95,
        "target_recall":       0.90,
        "max_fp_rate":         0.05,
        "class_weight_safe":   3.0,
        "class_weight_enc":    1.0,
        "cost_fp":             3.0,
        "cost_fn":             10.0,
        "rf_n_estimators":     300,
        "rf_max_depth":        None,
        "rf_min_samples_split": 4,
        "rf_min_samples_leaf": 2,
        "rf_random_state":     42,
        "calibration_method":   "isotonic",
        "cv_folds":            3,
        "smote_strategy":      "smote_tomek",
    },

    "scanner": {
        "max_workers":            8,
        "max_file_size_mb":       2048,
        "min_file_size_bytes":    64,
        "default_sensitivity":     "balanced",
        "available_sensitivities": ["balanced", "high_sensitivity", "paranoid"],
        "scan_extensions": [
            ".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".ppt", ".pptx",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico",
            ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".html", ".css", ".js", ".ts", ".py", ".java", ".cpp", ".c", ".h",
            ".exe", ".dll", ".sys", ".msi",
            ".json", ".xml", ".yaml", ".yml", ".toml",
            ".sql", ".db", ".sqlite",
        ],
    },

    "process_monitor": {
        "encryption_burst_threshold":  10,
        "encryption_burst_window":      30,
        "rapid_ops_threshold":           5,
        "rapid_ops_window":             10,
        "rename_burst_threshold":        5,
        "rename_burst_window":          10,
        "mass_io_threshold_mbps":       50,
        "mass_io_duration":             5,
        "suspicious_paths": [
            "temp", "tmp", "appdata\\local\\temp", "downloads",
        ],
    },

    "watchdog": {
        "debounce_seconds":   2.0,
        "queue_max_size":    500,
        "worker_threads":    3,
        "alert_threshold":   0.45,
        "scan_on_create":    True,
        "scan_on_modify":    True,
        "recursive":         True,
    },

    "fp_reducer": {
        "magic_bytes_multiplier":  0.70,
        "magic_mismatch_boost":    1.15,
        "default_threshold":       0.65,
        "extension_thresholds": {
            ".png":   0.80, ".jpg":   0.80, ".jpeg":  0.80,
            ".gif":   0.80, ".webp":  0.80,
            ".mp4":   0.82, ".mkv":   0.82, ".avi":   0.82, ".mov":   0.82,
            ".mp3":   0.80, ".aac":   0.80, ".flac":  0.78, ".opus":  0.80,
            ".zip":   0.82, ".gz":    0.82, ".bz2":   0.82,
            ".xz":    0.82, ".7z":    0.82, ".rar":   0.82, ".tar":   0.75,
            ".docx":  0.75, ".xlsx":  0.75, ".pptx":  0.75,
            ".exe":   0.85, ".dll":   0.85, ".so":    0.82,
            ".py":    0.60, ".js":    0.60, ".ts":    0.60, ".php":   0.60,
            ".pdf":   0.70,
            ".txt":   0.55, ".csv":   0.55, ".json":  0.55,
            ".xml":   0.55, ".html":  0.55, ".md":    0.55,
        },
    },

    "notifications": {
        "enabled":          True,
        "sound_enabled":     True,
        "toast_duration":   5,
        "min_level":        "LOW",   # LOW / MEDIUM / HIGH / CRITICAL
        "win32_toast":      True,
        "plyer_fallback":   True,
        "powershell_fallback": True,
    },

    "auto_response": {
        "enabled":                  True,
        "countdown_seconds":        30,
        "actions": {
            "CRITICAL": "auto_quarantine",
            "HIGH":     "ask_user",
            "MEDIUM":   "notify_only",
            "LOW":      "notify_only",
            "SAFE":     "none",
        },
    },

    "yara": {
        "auto_update":          False,
        "update_interval_hours": 24,
        "max_rules_per_scan":   100,
    },

    "network_monitor": {
        "enabled":              True,
        "dga_entropy_threshold": 3.5,
        "beacon_cov_max":       0.10,
        "connection_history_max": 100,
    },

    "ui": {
        "theme":             "dark",
        "accent_color":     "#3B82F6",
        "refresh_interval_ms": 150,
        "max_log_lines":    500,
        "chart_update_seconds": 2,
    },

    "logging": {
        "level":             "INFO",
        "log_dir":          "logs",
        "log_file":         "detector.log",
        "max_bytes":        5 * 1024 * 1024,
        "backup_count":     3,
        "console_level":    "WARNING",
    },

    # ─── VirusTotal Integration ─────────────────────────────────────────────
    "virustotal": {
        "api_key":         "",
        "cache_ttl_hours":  24,
        "rate_limit_rpm":   4,
        "enabled":         False,
        "auto_check":      False,
    },

    # ─── Entropy Monitoring ─────────────────────────────────────────────────
    "entropy": {
        "enabled":               True,
        "threshold":             7.5,
        "consecutive_files":     5,
        "time_window_seconds":   30,
        "entropy_alert_log":    "logs/entropy_alerts.log",
    },

    # ─── Honeypot Configuration ─────────────────────────────────────────────
    "honeypot": {
        "enabled":         False,
        "auto_deploy":     False,
        "names": [
            "passwords.xlsx",
            "backup.docx",
            "financial_report_2025.pdf",
            "company_secrets.txt",
            "wallet_keys.txt",
            "tax_returns_2024.pdf",
            "credentials.xlsx",
            "banking_info.xlsx",
            "private_keys.pem",
            "recovery_codes.txt",
        ],
        "locations": [
            "Desktop",
            "Documents",
            "Downloads",
        ],
        "max_per_location": 3,
    },

    # ─── FastAPI Server ────────────────────────────────────────────────────
    "api": {
        "enabled":                    False,
        "host":                      "0.0.0.0",
        "port":                      8000,
        "api_key":                   "",
        "jwt_secret":                "",
        "jwt_algorithm":             "HS256",
        "access_token_expire_minutes": 60,
        "reload":                    False,
    },

    # ─── ML Feedback Loop ──────────────────────────────────────────────────
    "ml_feedback": {
        "auto_retrain_threshold":    50,
        "retrain_interval_hours":    168,
        "auto_retrain_enabled":      False,
    },

    # ─── Office Document Scanner ───────────────────────────────────────────
    "office_scanner": {
        "enabled":      True,
        "yara_enabled": True,
        "max_file_size_mb": 100,
    },

    # ─── AI Analysis (Claude) ────────────────────────────────────────────────
    "ai": {
        "enabled":    True,
        "api_key":    "",
        # Model IDs via taphoaapi.info.vn proxy:
        #   'claude-sonnet-4-6'     → Claude Sonnet 4.6 (balanced, recommended)
        #   'claude-opus-4-6'       → Claude Opus 4.6 (most capable)
        #   'claude-haiku-4-5-20251001' → Claude Haiku 4.5 (fastest, lightweight)
        "model":      "claude-sonnet-4-6",
        "max_tokens": 1024,
        "temperature": 0.2,
    },
}


# ─── ConfigManager ────────────────────────────────────────────────────────────

class ConfigManager:
    """Thread-safe configuration manager with JSON persistence."""

    CONFIG_FILE = "data/config.json"

    def __init__(self):
        self._lock   = Lock()
        self._config = copy.deepcopy(DEFAULT_CONFIG)
        self._defaults = copy.deepcopy(DEFAULT_CONFIG)
        self._load()

    # ─── Persistence ─────────────────────────────────────────────────────────

    def _load(self):
        """Load configuration from JSON file if it exists."""
        path = self._resolve_path(self.CONFIG_FILE)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._deep_update(self._config, data)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load config file: {e}")

    def save(self) -> bool:
        """Persist current configuration to JSON file."""
        path = self._resolve_path(self.CONFIG_FILE)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            return True
        except (IOError, OSError):
            return False

    def reset_to_defaults(self):
        """Restore all settings to default values."""
        with self._lock:
            self._config = copy.deepcopy(self._defaults)

    # ─── Accessors ───────────────────────────────────────────────────────────

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get value using dot notation.

        Examples:
            config.get("ml.default_threshold")
            config.get("scanner.max_workers")
            config.get("nonexistent.key", "fallback")
        """
        with self._lock:
            keys = key_path.split(".")
            val  = self._config
            for k in keys:
                if isinstance(val, dict) and k in val:
                    val = val[k]
                else:
                    return default
            return val

    def set(self, key_path: str, value: Any, persist: bool = True) -> bool:
        """
        Set value using dot notation and optionally persist to file.

        Returns True if persisted successfully (or persist=False).
        """
        with self._lock:
            keys  = key_path.split(".")
            config = self._config
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            config[keys[-1]] = value

        if persist:
            return self.save()
        return True

    def get_all(self) -> Dict[str, Any]:
        """Return a deep copy of the entire configuration."""
        with self._lock:
            return copy.deepcopy(self._config)

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _deep_update(self, target: Dict, source: Dict):
        """Recursively merge source into target."""
        for key, val in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(val, dict):
                self._deep_update(target[key], val)
            else:
                target[key] = val

    def _resolve_path(self, path: str) -> str:
        """Resolve a relative path from the project root."""
        if os.path.isabs(path):
            return path
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, path)


# ─── Global Singleton ────────────────────────────────────────────────────────

_config_instance: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get the global ConfigManager singleton."""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance


# ─── Convenient alias ───────────────────────────────────────────────────────

config = get_config()
