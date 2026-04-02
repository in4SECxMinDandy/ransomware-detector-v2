import json
import logging
from typing import Dict, Any, Optional

import httpx

from core.config_manager import config

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    AI Analyzer using Anthropic (Claude Sonnet 4.6) API via taphoaapi.info.vn proxy.
    Uses httpx directly for full control over auth headers and request format.

    Supports two usage patterns:
      - analyze_threat(threat_data: dict)    → generic dict input
      - analyze_scan_result(scan_result)    → accepts a Scanner.ScanResult directly
    """

    API_VERSION = "2023-06-01"

    def __init__(self):
        if config.get("ai.enabled") is None:
            config.set("ai.enabled", True)
        if not config.get("ai.model"):
            config.set("ai.model", "claude-sonnet-4-6")

        self.api_key     = config.get("ai.api_key", "")
        self.auth_token  = config.get("ai.auth_token", "")
        self.base_url    = config.get("ai.base_url", "").rstrip("/")
        self.model       = config.get("ai.model", "claude-sonnet-4-6")
        self.max_tokens  = config.get("ai.max_tokens", 2048)
        self.temperature = config.get("ai.temperature", 0.2)
        self.enabled     = config.get("ai.enabled", True)

    def is_configured(self) -> bool:
        token = self.auth_token or self.api_key
        return self.enabled and bool(token)

    def _build_headers(self) -> Dict[str, str]:
        token = self.auth_token or self.api_key
        return {
            "x-api-key": token,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "anthropic-version": self.API_VERSION,
            "anthropic-dangerous-direct-password-access": "true",
        }

    @staticmethod
    def _format_behavior_context(raw: Dict[str, Any]) -> str:
        lines = [
            f"- Process: {raw.get('filename', 'unknown')} (PID: {raw.get('process_pid', 'N/A')})",
            f"- Behavior Type: {raw.get('behavior_type', 'unknown')}",
            f"- Process Path: {raw.get('process_path', 'N/A')}",
            f"- Severity: {raw.get('ml_risk_level', 'UNKNOWN')}",
        ]
        files = raw.get("affected_files") or []
        if files:
            lines.append(f"- Affected Files: {len(files)} file(s)")
            for f in files[:5]:
                lines.append(f"  • {f}")
            if len(files) > 5:
                lines.append(f"  ... and {len(files) - 5} more")
        desc = raw.get("alert_description", "")
        if desc:
            lines.append(f"- Description: {desc}")
        metadata = raw.get("alert_metadata") or {}
        if metadata:
            lines.append(f"- Metadata: {json.dumps(metadata, default=str)}")
        return "\n".join(lines)

    def analyze_threat(self, threat_data: Dict[str, Any]) -> str:
        """
        Send threat data to Claude via taphoaapi.info.vn proxy for analysis.
        threat_data expected shape:
        {
            "file_path": str,
            "filename": str,
            "size": int,
            "extension": str,
            "entropy": float,
            "entropy_z_score": float,      # z-score vs extension baseline
            "ext_baseline_mean": float,    # baseline entropy for this extension
            "ext_baseline_std": float,
            "raw_probability": float,
            "adjusted_probability": float,
            "ml_risk_level": str,
            "fp_adjusted": bool,
            "fp_reason": str,
            "sha256": str,
            # PE analysis (for .exe/.dll/.sys)
            "pe_info": {
                "is_packed": bool,
                "rwx_sections": list[str],
                "suspicious_sections": list[str],
                "has_overlay": bool,
                "sections_count": int,
            } | None,
            # YARA results
            "yara_matches": list[str],
            "yara_boosted": bool,
            # VirusTotal
            "vt_available": bool,
            "vt_detection_ratio": str,
            "vt_malicious_count": int,
            "vt_suspicious_count": int,
            "vt_total_engines": int,
            "vt_permalink": str,
            # Feature flags
            "magic_bytes_mismatch": bool,
            "known_benign_format": bool,
            "struct_consistency": float,
            "compression_ratio": float,
        }
        """
        if not self.is_configured():
            return "AI Analysis is not configured. Please check your API key."

        if not self.base_url:
            return "AI Analysis base URL is not configured. Please set the proxy URL in Settings."

        # ── Build structured threat context ──────────────────────────────────
        raw = threat_data

        # Entropy context
        ext = raw.get("extension", "unknown").lower().lstrip(".")
        ent = raw.get("entropy", 0.0)
        ent_z = raw.get("entropy_z_score", 0.0)
        baseline_mean = raw.get("ext_baseline_mean", 5.5)
        baseline_std = raw.get("ext_baseline_std", 2.0)

        # PE context
        pe = raw.get("pe_info") or {}
        pe_flags = []
        if pe.get("is_packed"):
            pe_flags.append(f"PACKED (sections: {pe.get('sections_count', '?')})")
        if pe.get("rwx_sections"):
            pe_flags.append(f"RWX sections: {', '.join(pe['rwx_sections'])}")
        if pe.get("suspicious_sections"):
            pe_flags.append(f"SUSPICIOUS sections: {', '.join(pe['suspicious_sections'])}")
        if pe.get("has_overlay"):
            pe_flags.append("HAS_OVERLAY")

        # YARA context
        yara_matches = raw.get("yara_matches") or []
        yara_str = ", ".join(yara_matches) if yara_matches else "None"
        _yara_note_text = (
            "- Note: YARA matches indicate pattern-based detection. Rule names (e.g., 'Clop_Marker') "
            "represent FAMILY HYPOTHESIS, not confirmed attribution. Treat as 'possible family' and "
            "require corroborating evidence (VT, behavior, code similarity) before asserting a specific "
            "ransomware family."
        )
        yara_note = _yara_note_text if yara_matches else ""

            # VT context
        vt = ""
        if raw.get("vt_available"):
            ratio = raw.get("vt_detection_ratio", "0/0")
            mal = raw.get("vt_malicious_count", 0)
            susp = raw.get("vt_suspicious_count", 0)
            total = raw.get("vt_total_engines", 0)
            permalink = raw.get("vt_permalink", "")
            vt = (
                f"Detection: {ratio} ({mal} malicious, {susp} suspicious / {total} engines)\n"
                f"Permalink: {permalink}"
            )
        else:
            vt = "Not queried or not available"

        # Threat Intelligence context
        ti_parts = []
        if raw.get("ti_available"):
            mb = raw.get("ti_mb_available")
            tf = raw.get("ti_tf_available")
            otx = raw.get("ti_otx_available")

            if mb:
                family = raw.get("ti_mb_family", "Unknown")
                sig = raw.get("ti_mb_signature", "")
                first_seen = raw.get("ti_mb_first_seen", "N/A")
                tags = raw.get("ti_mb_tags", [])
                delivery = raw.get("ti_mb_delivery_method", "N/A")
                ti_parts.append(
                    f"MalwareBazaar: FAMILY={family or sig or 'Unknown'} | "
                    f"First Seen={first_seen} | Delivery={delivery} | "
                    f"Tags={', '.join(tags) if tags else 'None'}"
                )

            if tf:
                threat_type = raw.get("ti_tf_threat_type", "N/A")
                family = raw.get("ti_tf_malware_family", "N/A")
                confidence = raw.get("ti_tf_confidence", 0)
                tags = raw.get("ti_tf_tags", [])
                ti_parts.append(
                    f"ThreatFox: Type={threat_type} | Family={family} | "
                    f"Confidence={confidence}% | Tags={', '.join(tags) if tags else 'None'}"
                )

            if otx:
                count = raw.get("ti_otx_pulse_count", 0)
                names = raw.get("ti_otx_pulse_names", [])
                meta = raw.get("ti_otx_analysis_metadata", {})
                pulse_list = ", ".join(names[:5]) if names else "None"
                ti_parts.append(
                    f"AlienVault OTX: {count} pulse(s) | Pulses={pulse_list} | "
                    f"Score={meta.get('score', 'N/A')}"
                )
        else:
            ti_parts.append("No Threat Intelligence data available")

        ti_context = "\n".join(ti_parts)

        # Feature flags
        flags = []
        if raw.get("magic_bytes_mismatch"):
            flags.append("MAGIC_BYTES_MISMATCH")
        if raw.get("known_benign_format"):
            flags.append("KNOWN_BENIGN_FORMAT")
        if raw.get("fp_adjusted"):
            flags.append(f"FP_REDUCED: {raw.get('fp_reason', '')}")
        if raw.get("yara_boosted"):
            flags.append("YARA_BOOSTED")
        flags_str = "; ".join(flags) if flags else "None"

        # ML context — show the full scoring pipeline so the AI (and human reader)
        # understands WHY the probability changed, not just the final number.
        raw_proba = raw.get("raw_probability", 0.0)
        adj_proba = raw.get("adjusted_probability", 0.0)
        ml_level = raw.get("ml_risk_level", "UNKNOWN")
        fp_reason = raw.get("fp_reason", "")

        # Parse fp_reason to show each adjustment step
        pipeline_steps = []
        if fp_reason:
            for part in fp_reason.split("|"):
                step = part.strip()
                if step:
                    pipeline_steps.append(f"  • {step}")

        pipeline_desc = "\n".join(pipeline_steps) if pipeline_steps else "  (no adjustments applied)"
        ml_context = (
            f"Raw ML probability: {raw_proba:.2%}\n"
            f"Final adjusted probability: {adj_proba:.2%}\n"
            f"ML Risk Level: {ml_level}\n"
            f"Adjustment pipeline:\n{pipeline_desc}"
        )

        # Entropy interpretation
        if ent_z > 2.0:
            ent_interpretation = "ABNORMALLY HIGH"
            ent_unusual_note = f"- This entropy level is unusual for .{ext} and warrants closer inspection"
        elif ent_z > -2.0:
            ent_interpretation = "WITHIN NORMAL RANGE"
            ent_unusual_note = ""
        else:
            ent_interpretation = "UNUSUALLY LOW"
            ent_unusual_note = ""

        # High-entropy file types where high entropy is expected
        high_ent_type = ext in {"exe", "dll", "sys", "zip", "png", "mp4"}
        ent_packing_note = (
            f"- Entropy is high for this file type; packing/obfuscation may be present"
            if high_ent_type and ent_z > 2.0
            else ""
        )

        prompt = f"""You are a senior cybersecurity malware analyst. Analyze the following threat and produce a structured incident response report.

## FILE IDENTIFICATION
- Filename: {raw.get("filename", "unknown")}
- Path: {raw.get("file_path", "unknown")}
- Size: {raw.get("size", 0) / (1024*1024):.2f} MB
- Extension: .{ext}
- SHA-256: {raw.get("sha256", "N/A")}

## ENTROPY ANALYSIS
- Raw Entropy: {ent:.3f} bits/byte
- Extension Baseline: {baseline_mean:.3f} ± {baseline_std:.3f}
- Z-Score vs Baseline: {ent_z:.2f}σ
- Interpretation: {ent_interpretation} for .{ext} files
{ent_packing_note}
{ent_unusual_note}

## MACHINE LEARNING ANALYSIS
{ml_context}

## PE STRUCTURAL ANALYSIS
{"; ".join(pe_flags) if pe_flags else "Not applicable (not a PE file)"}

## YARA SIGNATURE MATCHES
{yara_str}
{yara_note}

## VIRUSTOTAL INTELLIGENCE
{vt}

## THREAT INTELLIGENCE CORRELATION
{ti_context}

## STATISTICAL ANOMALY FLAGS
{flags_str}

## BEHAVIOR ANALYSIS (Live Process Monitoring)
{self._format_behavior_context(raw) if raw.get("behavior_type") else "N/A — file-based scan"}

## ANALYSIS REQUIREMENTS
1. **Entropy Assessment**: Compare entropy against the baseline for this file type.
   - For .exe/.dll: entropy 5.5-7.5 is normal; >7.5 with z>2.0 suggests packing/encryption
   - For compressed types (.zip, .png, .mp4): high entropy is expected and NOT suspicious by itself
   - Do NOT flag files as malicious based solely on entropy if baseline is already high

2. **Threat Intelligence Correlation**: Cross-reference TI data with local analysis:
   - If MalwareBazaar/ThreatFox/OTX report this hash as malicious ransomware family → UPGRADE risk level
   - Use TI malware family for ATT&CK attribution (e.g., "LockBit" → T1486, T1490)
   - If TI sources agree on ransomware family, increase confidence of CRITICAL classification
   - If TI sources report clean but ML/VT flag suspicious → INVESTIGATE FURTHER (new variant possible)

3. **Multi-Signal Correlation**: Require at least 2 independent indicators before CRITICAL:
   - ML probability >95% AND entropy anomaly AND VT detections
   - Single indicator (e.g., entropy alone) should result in MEDIUM/HIGH at most

4. **MITRE ATT&CK Mapping**: For each recommended action, map to ATT&CK technique IDs
   Example: "Delete Volume Shadow Copies" → T1486 (Data Encrypted for Impact)

5. **IOC Extraction**: Provide complete IOCs:
   - SHA-256 hash
   - Network patterns (C2 domains/IPs if inferable)
   - File-based IOCs (mutexes, registry keys, scheduled tasks)
   - Behavioral IOCs (commands, persistence mechanisms)

6. **Risk Level Justification**: Explicitly state which signals drove the final risk level

7. **VirusTotal Under-detection Discussion**: If VT detection is <80%, explicitly discuss:
   - The sample may be a new variant or repacked sample not yet broadly detected
   - AV engines with positive detections still carry significant weight
   - Low VT coverage does NOT imply the file is benign — false negatives are common for new malware

8. **Attribution Caution**: YARA rule family names and TI family names are heuristic indicators, not definitive attribution. Use phrasing like "indicators consistent with [FAMILY]" rather than "this is [FAMILY] ransomware".

---

## OUTPUT FORMAT

### Threat Summary
[Table: File | Size | Entropy | ML Prob | VT Ratio | Risk Level]

### Signal Analysis
[Bullet points: what each signal indicates, with confidence level]

### Entropy Deep-Dive
[Explain entropy finding relative to file type baseline]

### MITRE ATT&CK Mapping
[Table: Technique ID | Name | Observed/Expected | Evidence]

### Risk Assessment
[Detailed justification for risk level, citing specific signals]

### Potential Impact
[Table: Impact Area | Concern | Confidence]

### Recommended Incident Response Actions
[Phased: Immediate (0-1h) | Short-term (1-24h) | Medium-term (24-72h)]
[Each action with ATT&CK mapping]

### Indicators to Hunt
```
# File Hash
SHA-256: [hash]

# Behavioral Patterns
[commands/registry/network patterns]

# Network IOCs
[C2 domains, IPs, protocols]
```

### False Positive Assessment
[Could this be a legitimate file? What evidence supports or refutes FP?]

Report:"""

        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "system": "You are a cybersecurity expert analyzing potential malware and ransomware threats.",
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        try:
            with httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
                response = client.post(
                    f"{self.base_url}/v1/messages",
                    headers=self._build_headers(),
                    json=payload,
                )

            if response.status_code != 200:
                logger.error(f"Proxy API error ({response.status_code}): {response.text}")
                return f"API error ({response.status_code}): {response.text}"

            data = response.json()
            content = data.get("content", [])
            for block in content:
                if block.get("type") == "text":
                    return block["text"]

            return "AI returned an empty response."

        except httpx.TimeoutException as e:
            logger.error(f"Claude API timeout: {e}")
            return f"AI Analysis timeout: {e}"
        except httpx.HTTPStatusError as e:
            logger.error(f"Claude API HTTP error ({e.response.status_code}): {e.response.text}")
            return f"API error ({e.response.status_code}): {e.response.text}"
        except Exception as e:
            # [DEBUG] Instrument InvalidPort root cause
            import os as _os
            import traceback as _tb
            logger.error(
                f"[DEBUG AI] Exception type={type(e).__name__}  "
                f"HTTP_PROXY={_os.environ.get('HTTP_PROXY', '')!r}  "
                f"HTTPS_PROXY={_os.environ.get('HTTPS_PROXY', '')!r}  "
                f"base_url={self.base_url!r}  "
                f"trace={_tb.format_exc()}"
            )
            logger.error(f"Claude AI Analysis failed: {e}")
            return f"Error analyzing threat with AI: {str(e)}"

    def analyze_scan_result(self, scan_result) -> str:
        """
        Convenience method: accept a Scanner.ScanResult directly and forward
        to analyze_threat() after mapping all available fields.

        Requires core.scanner.ScanResult and core.feature_extractor.
        """
        try:
            from core.feature_extractor import EXTENSION_ENTROPY_BASELINE, DEFAULT_ENTROPY_BASELINE
        except ImportError:
            EXTENSION_ENTROPY_BASELINE = {}
            DEFAULT_ENTROPY_BASELINE = (5.5, 2.0)

        ext = scan_result.extension.lstrip(".").lower()
        baseline = EXTENSION_ENTROPY_BASELINE.get(ext, DEFAULT_ENTROPY_BASELINE)
        baseline_mean, baseline_std = baseline
        if baseline_std < 0.01:
            baseline_std = 0.01

        ent = scan_result.entropy
        ent_z = (ent - baseline_mean) / baseline_std

        pe_info = {}
        if scan_result.pe_info:
            if isinstance(scan_result.pe_info, dict):
                pe_info = scan_result.pe_info
            else:
                # duck-type: PEAnalysisResult object
                pe_info = {
                    "is_packed": getattr(scan_result.pe_info, "is_packed", False),
                    "rwx_sections": getattr(scan_result.pe_info, "rwx_sections", []),
                    "suspicious_sections": getattr(scan_result.pe_info, "suspicious_sections", []),
                    "has_overlay": getattr(scan_result.pe_info, "has_overlay", False),
                    "sections_count": getattr(scan_result.pe_info, "sections_count", 0),
                }

        yara_match_names = [
            getattr(m, "rule_name", str(m)) if hasattr(m, "rule_name") else str(m)
            for m in (scan_result.yara_matches or [])
        ]

        threat_data = {
            "file_path": scan_result.path,
            "filename": scan_result.filename,
            "size": scan_result.size,
            "extension": scan_result.extension,
            "entropy": ent,
            "entropy_z_score": float(ent_z),
            "ext_baseline_mean": float(baseline_mean),
            "ext_baseline_std": float(baseline_std),
            "raw_probability": scan_result.raw_probability,
            "adjusted_probability": scan_result.probability,
            "ml_risk_level": scan_result.risk_level,
            "fp_adjusted": scan_result.fp_adjusted,
            "fp_reason": scan_result.fp_reason,
            "sha256": scan_result.sha256,
            "pe_info": pe_info,
            "yara_matches": yara_match_names,
            "yara_boosted": scan_result.yara_boosted,
            "vt_available": scan_result.vt_available,
            "vt_detection_ratio": scan_result.vt_detection_ratio,
            "vt_malicious_count": scan_result.vt_malicious_count,
            "vt_suspicious_count": scan_result.vt_suspicious_count,
            "vt_total_engines": scan_result.vt_total_engines,
            "vt_permalink": scan_result.vt_permalink,
            "magic_bytes_mismatch": False,  # not stored in ScanResult; inferred by PE layer
            "known_benign_format": bool(scan_result.pe_info.get("is_packed") is False)
                if isinstance(scan_result.pe_info, dict) else False,
            "struct_consistency": 0.0,  # chunk-level; ScanResult doesn't persist it
            "compression_ratio": 0.0,
            # v3.5: Threat Intelligence Correlation
            "ti_available":              scan_result.ti_available,
            "ti_mb_available":           scan_result.ti_mb_available,
            "ti_mb_family":              scan_result.ti_mb_family,
            "ti_mb_signature":           scan_result.ti_mb_signature,
            "ti_mb_first_seen":          scan_result.ti_mb_first_seen,
            "ti_mb_tags":                scan_result.ti_mb_tags,
            "ti_mb_delivery_method":     scan_result.ti_mb_delivery_method,
            "ti_tf_available":           scan_result.ti_tf_available,
            "ti_tf_threat_type":         scan_result.ti_tf_threat_type,
            "ti_tf_malware_family":      scan_result.ti_tf_malware_family,
            "ti_tf_confidence":          scan_result.ti_tf_confidence,
            "ti_tf_tags":                scan_result.ti_tf_tags,
            "ti_otx_available":          scan_result.ti_otx_available,
            "ti_otx_pulse_count":        scan_result.ti_otx_pulse_count,
            "ti_otx_pulse_names":        scan_result.ti_otx_pulse_names,
            "ti_otx_analysis_metadata":  scan_result.ti_otx_analysis_metadata,
        }
        return self.analyze_threat(threat_data)


# Singleton instance access
_ai_analyzer_instance: Optional[AIAnalyzer] = None


def get_ai_analyzer() -> AIAnalyzer:
    global _ai_analyzer_instance
    if _ai_analyzer_instance is None:
        _ai_analyzer_instance = AIAnalyzer()
    return _ai_analyzer_instance
