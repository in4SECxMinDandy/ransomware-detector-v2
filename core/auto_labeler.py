"""
auto_labeler.py
================
Rule-based auto-labeling for high-confidence training samples.
"""

from __future__ import annotations

from typing import Any, Dict, List


CONFIDENCE_RANK = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


def normalize_label(label: str | None) -> str | None:
    value = str(label or "").strip().upper()
    aliases = {
        "SAFE": "SAFE",
        "BENIGN": "SAFE",
        "CLEAN": "SAFE",
        "ENCRYPTED": "ENCRYPTED",
        "RANSOMWARE": "ENCRYPTED",
        "MALICIOUS": "ENCRYPTED",
        "MALWARE": "ENCRYPTED",
        "THREAT": "ENCRYPTED",
    }
    return aliases.get(value)


def auto_label_sample(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Auto-label a sample from local evidence only.

    Returns:
        {"label": "SAFE|ENCRYPTED|UNKNOWN", "confidence": "...", "score": int, "reasons": [...]}
    """
    source = str(evidence.get("source", "")).lower()
    reasons: List[str] = []
    malicious_score = 0
    safe_score = 0

    feedback_label = normalize_label(evidence.get("feedback_label"))
    if feedback_label:
        return {
            "label": feedback_label,
            "confidence": "high",
            "score": 10,
            "reasons": [f"feedback:{feedback_label.lower()}"],
        }

    if evidence.get("whitelisted") or "whitelist" in str(evidence.get("fp_reason", "")).lower():
        safe_score += 6
        reasons.append("whitelist")

    if evidence.get("honeypot_triggered"):
        malicious_score += 7
        reasons.append("honeypot_triggered")

    quarantine_reason = str(evidence.get("quarantine_reason", "")).lower()
    if evidence.get("quarantined"):
        if any(token in quarantine_reason for token in ("critical", "high", "threat", "ransom")):
            malicious_score += 7
            reasons.append("quarantine_reason")
        else:
            malicious_score += 3
            reasons.append("quarantined")

    yara_count = int(evidence.get("yara_match_count", 0) or 0)
    yara_severities = [str(s).upper() for s in evidence.get("yara_severities", [])]
    if yara_count:
        if "CRITICAL" in yara_severities:
            malicious_score += 6
            reasons.append("yara_critical")
        elif "HIGH" in yara_severities:
            malicious_score += 4
            reasons.append("yara_high")
        else:
            malicious_score += 2
            reasons.append("yara_medium")

    pe_info = evidence.get("pe_info") or {}
    if pe_info:
        suspicious_sections = pe_info.get("suspicious_sections") or []
        rwx_sections = pe_info.get("rwx_sections") or []
        if suspicious_sections or rwx_sections:
            malicious_score += 2
            reasons.append("pe_suspicious")
        if pe_info.get("is_packed"):
            malicious_score += 1
            reasons.append("pe_packed")

    risk_level = str(evidence.get("risk_level", "")).upper()
    if risk_level == "CRITICAL":
        malicious_score += 2
        reasons.append("risk_critical")
    elif risk_level == "HIGH":
        malicious_score += 1
        reasons.append("risk_high")
    elif risk_level in {"SAFE", "LOW"}:
        safe_score += 1
        reasons.append("risk_safeish")

    probability = float(evidence.get("probability", 0.0) or 0.0)
    if probability >= 0.98:
        malicious_score += 1
        reasons.append("probability_very_high")
    elif probability <= 0.10:
        safe_score += 2
        reasons.append("probability_very_low")

    trigger_reason = str(evidence.get("trigger_reason", "")).lower()
    if any(token in trigger_reason for token in ("destructive", "multiple access", "modified", "deleted")):
        malicious_score += 3
        reasons.append("trigger_reason")

    if source == "scan_history":
        if not yara_count and not evidence.get("quarantined") and risk_level in {"SAFE", "LOW"} and probability <= 0.05:
            safe_score += 2
            reasons.append("clean_scan_history")

    if malicious_score >= 7 and malicious_score >= safe_score + 2:
        return {
            "label": "ENCRYPTED",
            "confidence": "high",
            "score": malicious_score,
            "reasons": reasons,
        }
    if malicious_score >= 5 and malicious_score >= safe_score + 2:
        return {
            "label": "ENCRYPTED",
            "confidence": "medium",
            "score": malicious_score,
            "reasons": reasons,
        }
    if safe_score >= 6 and safe_score >= malicious_score + 2:
        return {
            "label": "SAFE",
            "confidence": "high",
            "score": safe_score,
            "reasons": reasons,
        }
    if safe_score >= 4 and safe_score >= malicious_score + 2:
        return {
            "label": "SAFE",
            "confidence": "medium",
            "score": safe_score,
            "reasons": reasons,
        }
    return {
        "label": "UNKNOWN",
        "confidence": "unknown",
        "score": max(malicious_score, safe_score),
        "reasons": reasons,
    }
