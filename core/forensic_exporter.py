"""
forensic_exporter.py
====================
Task 2: Forensic Bundle Exporter.

Creates forensic export bundles containing:
  - hashes.json: File hash manifest
  - ioc_report.json: STIX 2.1 format IOC report
  - timeline.csv: Chronological events
  - summary.txt: Human-readable report

Usage:
    exporter = ForensicBundleExporter()
    bundle_path = exporter.export(scan_results, "C:\\output\\dir")
"""

import os
import json
import uuid
import socket
import hashlib
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from zipfile import ZipFile, ZIP_DEFLATED

try:
    import stix2
    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False
    logging.warning("stix2 not available - using manual JSON format for IOC report")

logger = logging.getLogger(__name__)


class ForensicBundleExporter:
    """
    Forensic Bundle Exporter - Creates exportable forensic bundles.
    """

    def __init__(self):
        self.hostname = socket.gethostname()

    def export(self, scan_results: List[Any], output_dir: str) -> str:
        """
        Creates forensic bundle ZIP file.

        Args:
            scan_results: List of ScanResult objects
            output_dir: Output directory path

        Returns:
            Path to the created ZIP file

        Raises:
            IOError: If unable to create output directory or write files
        """
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        bundle_name = f"forensic_{timestamp}_{self.hostname}"
        bundle_path = os.path.join(output_dir, f"{bundle_name}.zip")

        # Prepare data
        files_data = self._prepare_files_data(scan_results)
        ioc_data = self._prepare_ioc_data(files_data)
        timeline_data = self._prepare_timeline_data(scan_results)
        summary = self._prepare_summary(scan_results, files_data)

        # Create ZIP
        try:
            with ZipFile(bundle_path, 'w', ZIP_DEFLATED) as zf:
                # Write hashes.json
                hashes_json = self._create_hashes_json(files_data)
                zf.writestr("hashes.json", hashes_json)

                # Write ioc_report.json
                ioc_json = self._create_ioc_json(ioc_data)
                zf.writestr("ioc_report.json", ioc_json)

                # Write timeline.csv
                timeline_csv = self._create_timeline_csv(timeline_data)
                zf.writestr("timeline.csv", timeline_csv)

                # Write summary.txt
                zf.writestr("summary.txt", summary)

            logger.info(f"Forensic bundle created: {bundle_path}")
            return bundle_path

        except IOError as e:
            logger.error(f"Failed to create forensic bundle: {e}")
            raise

    def _prepare_files_data(self, scan_results: List[Any]) -> List[Dict[str, Any]]:
        """Prepare file data from scan results."""
        files_data = []

        for result in scan_results:
            try:
                file_info = {
                    "path": result.path,
                    "filename": result.filename,
                    "md5": getattr(result, "md5", None) or self._compute_hash(result.path, "md5"),
                    "sha1": getattr(result, "sha1", None) or self._compute_hash(result.path, "sha1"),
                    "sha256": getattr(result, "sha256", None) or self._compute_hash(result.path, "sha256"),
                    "threat_score": result.probability,
                    "yara_matches": getattr(result, "yara_matches", []) or [],
                    "entropy": result.entropy,
                    "risk_level": result.risk_level,
                    "size": result.size,
                }
                files_data.append(file_info)
            except Exception as e:
                logger.warning(f"Failed to process file {result.path}: {e}")

        return files_data

    def _prepare_ioc_data(self, files_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prepare IOC data from file data."""
        iocs = []

        for file_info in files_data:
            # Only include malicious files as IOCs
            if file_info.get("threat_score", 0) >= 0.65 or file_info.get("risk_level") in ["CRITICAL", "HIGH"]:
                ioc = {
                    "path": file_info["path"],
                    "sha256": file_info["sha256"],
                    "md5": file_info["md5"],
                    "threat_score": file_info["threat_score"],
                    "yara_matches": file_info.get("yara_matches", []),
                }
                iocs.append(ioc)

        return iocs

    def _prepare_timeline_data(self, scan_results: List[Any]) -> List[Dict[str, Any]]:
        """Prepare timeline data from scan results."""
        timeline = []

        for result in scan_results:
            if result.risk_level in ["CRITICAL", "HIGH"]:
                timeline.append({
                    "timestamp": datetime.now().isoformat(),
                    "file_path": result.path,
                    "event_type": "FILE_DETECTED",
                    "severity": result.risk_level,
                    "threat_score": result.probability,
                })

        return timeline

    def _prepare_summary(self, scan_results: List[Any], files_data: List[Dict[str, Any]]) -> str:
        """Prepare human-readable summary."""
        total_files = len(scan_results)
        threats = sum(1 for r in scan_results if r.risk_level in ["CRITICAL", "HIGH"])
        critical_count = sum(1 for r in scan_results if r.risk_level == "CRITICAL")
        high_count = sum(1 for r in scan_results if r.risk_level == "HIGH")

        # Get top IOCs
        threat_files = sorted(
            [f for f in files_data if f.get("threat_score", 0) >= 0.65],
            key=lambda x: x.get("threat_score", 0),
            reverse=True
        )[:5]

        top_iocs = [f["sha256"][:16] + "..." for f in threat_files if f.get("sha256")]

        summary = f"""=== FORENSIC SUMMARY ===
Hostname   : {self.hostname}
Scan Time  : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Total Files: {total_files:,}
Threats    : {threats} (CRITICAL: {critical_count}, HIGH: {high_count})
Top IOCs   : {', '.join(top_iocs) if top_iocs else 'None'}

=== DETECTION BREAKDOWN ===
"""

        # Add detection breakdown
        risk_counts = {}
        for r in scan_results:
            risk = r.risk_level or "UNKNOWN"
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        for risk, count in sorted(risk_counts.items()):
            summary += f"  {risk:12}: {count:>6}\n"

        summary += "\n=== FILES SCANNED ===\n"
        for r in scan_results[:20]:
            summary += f"  {r.risk_level:10} | {r.entropy:.4f} | {r.filename}\n"

        if len(scan_results) > 20:
            summary += f"  ... and {len(scan_results) - 20} more files\n"

        return summary

    def _compute_hash(self, file_path: str, algorithm: str) -> Optional[str]:
        """Compute hash of a file."""
        if not os.path.exists(file_path):
            return None

        try:
            hash_func = getattr(hashlib, algorithm)()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            logger.warning(f"Failed to compute {algorithm} for {file_path}: {e}")
            return None

    def _create_hashes_json(self, files_data: List[Dict[str, Any]]) -> str:
        """Create hashes.json content."""
        data = {
            "scan_time": datetime.now().isoformat(),
            "hostname": self.hostname,
            "files": files_data,
        }
        return json.dumps(data, indent=2)

    def _create_ioc_json(self, ioc_data: List[Dict[str, Any]]) -> str:
        """Create IOC report in STIX 2.1 format or manual JSON."""
        if STIX_AVAILABLE:
            return self._create_stix_bundle(ioc_data)
        else:
            return self._create_manual_ioc_json(ioc_data)

    def _create_stix_bundle(self, ioc_data: List[Dict[str, Any]]) -> str:
        """Create STIX 2.1 bundle."""
        bundle_objects = []

        for ioc in ioc_data:
            # Create indicator object
            indicator = stix2.Indicator(
                id=f"indicator--{uuid.uuid4()}",
                pattern=f"[file:hashes.'SHA-256' = '{ioc['sha256']}']",
                labels=["malicious-activity"],
                name=f"Ransomware IOC - {ioc['filename']}",
                pattern_type="stix",
                valid_from=datetime.now().isoformat(),
            )
            bundle_objects.append(indicator)

        # Create bundle
        bundle = stix2.Bundle(
            id=f"bundle--{uuid.uuid4()}",
            objects=bundle_objects,
        )

        return bundle.serialize(pretty=True)

    def _create_manual_ioc_json(self, ioc_data: List[Dict[str, Any]]) -> str:
        """Create manual IOC JSON (fallback when stix2 not available)."""
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [],
        }

        for ioc in ioc_data:
            indicator = {
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "pattern": f"[file:hashes.SHA256 = '{ioc['sha256']}']",
                "labels": ["malicious-activity"],
                "name": "Ransomware IOC",
                "description": f"Detected threat score: {ioc['threat_score']:.2f}",
            }
            bundle["objects"].append(indicator)

        return json.dumps(bundle, indent=2)

    def _create_timeline_csv(self, timeline_data: List[Dict[str, Any]]) -> str:
        """Create timeline.csv content."""
        if not timeline_data:
            return "timestamp,file_path,event_type,severity,threat_score\n"

        output = "timestamp,file_path,event_type,severity,threat_score\n"
        for event in timeline_data:
            output += f"{event['timestamp']},{event['file_path']},{event['event_type']},{event['severity']},{event['threat_score']:.4f}\n"

        return output


def export_forensic_bundle(scan_results: List[Any], output_dir: str) -> str:
    """
    Convenience function to export forensic bundle.

    Args:
        scan_results: List of ScanResult objects
        output_dir: Output directory path

    Returns:
        Path to the created ZIP file
    """
    exporter = ForensicBundleExporter()
    return exporter.export(scan_results, output_dir)
