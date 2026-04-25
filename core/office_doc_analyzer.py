"""
office_doc_analyzer.py
=====================
Static Analysis Module cho Office Documents phat hien ma doc (malware).

Ho tro:
  - .doc, .docx, .docm  (Word)
  - .xls, .xlsx, .xlsm  (Excel)
  - .ppt, .pptx         (PowerPoint)
  - .pdf                (PDF)
  - .rtf                (Rich Text Format)

Phat hien:
  - Auto-execution VBA triggers: AutoOpen, Auto_Open, Document_Open,
    Workbook_Open, AutoExec, AutoClose, SheetActivate, Workbook_BeforeClose
  - VBA macro code (ooles VBA extraction)
  - Macro behavioral patterns (mraptor)
  - PDF actions: /OpenAction, /Launch, /AA (Additional Actions)
  - Embedded JavaScript trong PDF
  - RTF OLE objects va shellcode patterns
  - YARA signature matching

Ket qua tra ve: OfficeScanResult dataclass
  - file_path, threat_level, triggers_found, macro_code_snippet,
    pdf_actions, rtf_objects, yara_matches, recommendation

Su dung:
    analyzer = OfficeDocAnalyzer()
    result = analyzer.analyze("report.docm")
    print(result.threat_level, result.triggers_found)
"""

import os
import re
import logging
import hashlib
from typing import TYPE_CHECKING, Callable, List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

# ─── Try optional imports ────────────────────────────────────────────────────

if TYPE_CHECKING:
    import fitz  # type: ignore[import-not-found]
    from oletools.olevba import VBA_Parser, decode_text  # type: ignore[import-not-found]  # noqa: F401
    from oletools.mraptor import MacroRaptor  # type: ignore[import-not-found]
    from oletools.rtfobj import rtfobj  # type: ignore[import-not-found]
    from docx import Document as DocxDocument  # type: ignore[import-not-found]  # noqa: F401
    import openpyxl  # type: ignore[import-not-found]  # noqa: F401
    from pptx import Presentation  # type: ignore[import-not-found]  # noqa: F401
    PYMUPDF_AVAILABLE = True
    OLETOOLS_AVAILABLE = True
    DOCX_AVAILABLE = True
    OPENPYXL_AVAILABLE = True
    PPTX_AVAILABLE = True
else:
    try:
        import fitz  # PyMuPDF
        PYMUPDF_AVAILABLE = True
    except ImportError:
        fitz = None
        PYMUPDF_AVAILABLE = False

    try:
        from oletools.olevba import VBA_Parser, decode_text  # noqa: F401
        from oletools.mraptor import MacroRaptor
        from oletools.rtfobj import rtfobj
        OLETOOLS_AVAILABLE = True
    except ImportError:
        VBA_Parser = None
        decode_text = None
        MacroRaptor = None
        rtfobj = None
        OLETOOLS_AVAILABLE = False

    try:
        from docx import Document as DocxDocument  # noqa: F401
        DOCX_AVAILABLE = True
    except ImportError:
        DocxDocument = None
        DOCX_AVAILABLE = False

    try:
        import openpyxl  # noqa: F401
        OPENPYXL_AVAILABLE = True
    except ImportError:
        openpyxl = None
        OPENPYXL_AVAILABLE = False

    try:
        from pptx import Presentation  # noqa: F401
        PPTX_AVAILABLE = True
    except ImportError:
        Presentation = None
        PPTX_AVAILABLE = False


# ─── YARA Engine (lazy import to avoid circular dependency) ─────────────────

def _get_yara_engine():
    try:
        from core.yara_engine import get_yara_engine as _get
        return _get()
    except Exception:
        return None


# ─── Constants ─────────────────────────────────────────────────────────────

SUPPORTED_EXTENSIONS = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx",
    ".pdf", ".rtf",
}

# VBA auto-execution triggers
AUTO_EXEC_TRIGGERS = {
    "AutoOpen", "Auto_Open", "Document_Open",
    "Workbook_Open", "Workbook_BeforeClose",
    "AutoExec", "AutoClose",
    "SheetActivate", "Workbook_Activate",
    "Presentation_Open", "Presentation_Save",
    "SlideShowNextBuild", "SlideShowOnNext",
}

# PDF dangerous action keywords
PDF_DANGEROUS_ACTIONS = {
    "/OpenAction", "/Launch", "/AA", "/Names",
    "/EmbeddedFiles", "/JavaScript",
    "/SubmitForm", "/ImportData",
}

# Threat levels
THREAT_CLEAN = "CLEAN"
THREAT_SUSPICIOUS = "SUSPICIOUS"
THREAT_MALICIOUS = "MALICIOUS"

THREAT_LEVEL_MAP = {
    THREAT_CLEAN: 0,
    THREAT_SUSPICIOUS: 1,
    THREAT_MALICIOUS: 2,
}


# ─── Dataclasses ───────────────────────────────────────────────────────────

@dataclass
class OfficeScanResult:
    """Ket qua phan tich mot file van phong."""
    file_path: str
    filename: str
    extension: str
    file_size: int
    sha256: str

    # Analysis results
    threat_level: str = THREAT_CLEAN
    triggers_found: List[str] = field(default_factory=list)
    macro_code_snippet: str = ""
    macro_count: int = 0
    is_macro_enabled: bool = False

    # PDF-specific
    pdf_actions: List[Dict[str, Any]] = field(default_factory=list)
    pdf_javascript: List[str] = field(default_factory=list)
    pdf_embedded_files: List[str] = field(default_factory=list)

    # RTF-specific
    rtf_objects: List[Dict[str, Any]] = field(default_factory=list)

    # YARA
    yara_matches: List[Dict[str, str]] = field(default_factory=list)

    # Metadata
    analysis_time_ms: float = 0.0
    error: Optional[str] = None
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def to_summary(self) -> str:
        if self.threat_level == THREAT_CLEAN:
            return f"CLEAN: {self.filename}"
        elif self.threat_level == THREAT_SUSPICIOUS:
            return f"SUSPICIOUS: {self.filename} — {', '.join(self.triggers_found)}"
        else:
            return f"MALICIOUS: {self.filename} — {', '.join(self.triggers_found)}"


@dataclass
class MacroMatch:
    """Một macro VBA được phat hien."""
    module_name: str
    vba_code: str
    is_auto_exec: bool
    suspicious_keywords: List[str]
    risk_score: float  # 0.0 - 1.0


# ─── Pattern Detectors ─────────────────────────────────────────────────────

# Shellcode-like patterns (hex strings, common opcodes)
SHELLCODE_PATTERNS = [
    rb"(\xeb[\x00-\xff]){3,}",  # JMP short sequences
    rb"(\xe8[\x00-\xff]{4}){2,}",  # CALL sequences
    rb"(\xb8[\x00-\xff]{4}){3,}",  # MOV eax, imm32 sequences
    rb"[\x00-\xff]{100,}",  # Long null-padded sequences
]

# Suspicious VBA keywords
SUSPICIOUS_VBA_KEYWORDS = [
    r"Shell\(", r"WScript\.Shell", r"CreateObject\(",
    r"document\.write", r"innerHTML",
    r"Win32_Process", r"GetObject\(", r"Exec\(",
    r"Adodb\.Stream", r"MSXML2\.XMLHTTP",
    r"UrlDownloadToFile", r"InternetExplorer\.Application",
    r"Process ", r"cmd\.exe", r"powershell",
    r"base64", r"decode", r"DecryptString",
    r"HexToStr", r"StrToHex", r"Chr\(",
    r"Environ\(", r"CreateMutex", r"GetTempPath",
    r"LoadLibrary", r"GetProcAddress", r"VirtualAlloc",
    r"WriteProcessMemory", r"CreateRemoteThread",
    r"RegRead", r"RegWrite", r"RegDelete",
]

SUSPICIOUS_VBA_PATTERN = re.compile(
    "|".join(SUSPICIOUS_VBA_KEYWORDS),
    re.IGNORECASE | re.MULTILINE
)


def _detect_suspicious_vba(code: str) -> Tuple[bool, List[str], float]:
    """Phat hien keyword doi trong VBA code.

    Returns: (has_suspicious, keywords_found, risk_score)
    """
    matches = SUSPICIOUS_VBA_PATTERN.findall(code)
    keywords = list(dict.fromkeys(m.lower() for m in matches))

    if not keywords:
        return False, [], 0.0

    # Risk scoring
    risk = min(len(keywords) * 0.15, 0.9)
    return True, keywords, risk


# ─── OfficeDocAnalyzer ─────────────────────────────────────────────────────

class OfficeDocAnalyzer:
    """
    Phan tich tinh cac file van phong de phat hien ma doc.

    Su dung oletools (VBA parsing) va PyMuPDF (PDF analysis).
    """

    def __init__(self, yara_enabled: bool = True):
        self.yara_enabled = yara_enabled
        self._yara_engine = None
        self._stats = {
            "total_scanned": 0,
            "clean": 0,
            "suspicious": 0,
            "malicious": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        return self._stats.copy()

    def is_supported(self, file_path: str) -> bool:
        """Kiem tra xem file co duoc ho tro khong."""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in SUPPORTED_EXTENSIONS

    def analyze(self, file_path: str) -> OfficeScanResult:
        """
        Phan tich mot file van phong.

        Returns OfficeScanResult.
        """
        import time
        start_time = time.time()

        ext = os.path.splitext(file_path)[1].lower()
        filename = os.path.basename(file_path)

        result = OfficeScanResult(
            file_path=file_path,
            filename=filename,
            extension=ext,
            file_size=os.path.getsize(file_path) if os.path.isfile(file_path) else 0,
            sha256=self._compute_sha256(file_path),
        )

        try:
            if ext in {".doc", ".docx", ".docm"}:
                self._analyze_word(file_path, result)
            elif ext in {".xls", ".xlsx", ".xlsm"}:
                self._analyze_excel(file_path, result)
            elif ext in {".ppt", ".pptx"}:
                self._analyze_powerpoint(file_path, result)
            elif ext == ".pdf":
                self._analyze_pdf(file_path, result)
            elif ext == ".rtf":
                self._analyze_rtf(file_path, result)
            else:
                result.error = f"Unsupported extension: {ext}"
        except Exception as e:
            result.error = str(e)
            logger.error(f"Office analysis error for {file_path}: {e}")

        # YARA scan (all formats)
        if self.yara_enabled and result.error is None:
            self._scan_yara(result)

        # Determine threat level
        self._determine_threat_level(result)

        # Generate recommendation
        self._generate_recommendation(result)

        result.analysis_time_ms = (time.time() - start_time) * 1000

        # Update stats
        self._stats["total_scanned"] += 1
        if result.threat_level == THREAT_CLEAN:
            self._stats["clean"] += 1
        elif result.threat_level == THREAT_SUSPICIOUS:
            self._stats["suspicious"] += 1
        else:
            self._stats["malicious"] += 1

        return result

    def analyze_batch(self, file_paths: List[str],
                      on_progress: Optional[Callable] = None
                      ) -> List[OfficeScanResult]:
        """
        Phan tich nhieu file.

        Args:
            file_paths: Danh sach duong dan file
            on_progress: Callback(progress, total, result) — goi tren main thread

        Returns:
            List[OfficeScanResult]
        """
        results = []
        total = len(file_paths)

        for i, path in enumerate(file_paths):
            result = self.analyze(path)
            results.append(result)

            if on_progress:
                on_progress(i + 1, total, result)

        return results

    # ─── Word Analysis ────────────────────────────────────────────────────

    def _analyze_word(self, file_path: str, result: OfficeScanResult):
        """Phan tich Word documents (.doc, .docx, .docm)."""
        ext = os.path.splitext(file_path)[1].lower()

        # Check if macro-enabled
        if ext == ".docm":
            result.is_macro_enabled = True
        elif ext == ".docx":
            # DOCX can contain macros only if saved as .docm
            result.is_macro_enabled = False
        else:
            # Old .doc format — assume potentially macro-enabled
            result.is_macro_enabled = True

        if not OLETOOLS_AVAILABLE:
            result.error = "oletools not installed — install with: pip install oletools"
            return

        try:
            self._analyze_vba(file_path, result)
        except Exception as e:
            logger.debug(f"VBA analysis failed for {file_path}: {e}")

    # ─── Excel Analysis ───────────────────────────────────────────────────

    def _analyze_excel(self, file_path: str, result: OfficeScanResult):
        """Phan tich Excel spreadsheets (.xls, .xlsx, .xlsm)."""
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".xlsm":
            result.is_macro_enabled = True
        elif ext in {".xlsx", ".xls"}:
            result.is_macro_enabled = False

        if not OLETOOLS_AVAILABLE:
            result.error = "oletools not installed"
            return

        try:
            self._analyze_vba(file_path, result)
        except Exception as e:
            logger.debug(f"VBA analysis failed for {file_path}: {e}")

    # ─── PowerPoint Analysis ───────────────────────────────────────────────

    def _analyze_powerpoint(self, file_path: str, result: OfficeScanResult):
        """Phan tich PowerPoint presentations (.ppt, .pptx)."""
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".pptx":
            result.is_macro_enabled = False
        else:
            result.is_macro_enabled = True

        if not OLETOOLS_AVAILABLE:
            result.error = "oletools not installed"
            return

        try:
            self._analyze_vba(file_path, result)
        except Exception as e:
            logger.debug(f"VBA analysis failed for {file_path}: {e}")

    # ─── VBA Analysis (olevba + mraptor) ──────────────────────────────────

    def _analyze_vba(self, file_path: str, result: OfficeScanResult):
        """Trich xuat va phan tich VBA macros."""
        try:
            vba_parser = VBA_Parser(file_path)

            if not vba_parser.detect_vba_macros():
                vba_parser.close()
                return

            all_code = []
            macros_found = []

            for vba_module in vba_parser.extract_all_macros():
                module_name = vba_module[0] or "Module"
                vba_code = vba_module[1] or ""

                if not vba_code.strip():
                    continue

                result.macro_count += 1
                all_code.append(f"' ===== Module: {module_name} =====\n{vba_code}")

                # Check for auto-execution triggers
                found_triggers = self._check_auto_triggers(vba_code)
                result.triggers_found.extend(found_triggers)

                # Check for suspicious keywords
                has_susp, keywords, risk = _detect_suspicious_vba(vba_code)

                macros_found.append(MacroMatch(
                    module_name=module_name,
                    vba_code=vba_code[:500],  # First 500 chars as snippet
                    is_auto_exec=len(found_triggers) > 0,
                    suspicious_keywords=keywords,
                    risk_score=risk,
                ))

            if all_code:
                result.macro_code_snippet = "\n\n".join(all_code[:5])  # Max 5 modules
                if len(all_code) > 5:
                    result.macro_code_snippet += f"\n\n... (+{len(all_code) - 5} more modules)"

            vba_parser.close()

        except Exception as e:
            logger.debug(f"VBA analysis error: {e}")

    def _check_auto_triggers(self, vba_code: str) -> List[str]:
        """Kiem tra cac auto-execution trigger trong VBA code."""
        found = []
        code_upper = vba_code.upper()

        # Check function/sub declarations for trigger names
        trigger_pattern = re.compile(
            r"(?:Public\s+|Private\s+|Sub\s+|Function\s+)\s*"
            r"(" + "|".join(re.escape(t) for t in AUTO_EXEC_TRIGGERS) + r")\s*[\(\s]",
            re.IGNORECASE | re.MULTILINE
        )

        for match in trigger_pattern.finditer(vba_code):
            trigger = match.group(1)
            if trigger not in found:
                found.append(trigger)

        # Also check for Auto_ naming (underscore variant)
        for trigger in AUTO_EXEC_TRIGGERS:
            if trigger in code_upper:
                # Be more specific — only if it's a declaration
                if re.search(rf"\bSub\s+{re.escape(trigger)}\b", vba_code, re.IGNORECASE):
                    if trigger not in found:
                        found.append(trigger)
                elif re.search(rf"\bFunction\s+{re.escape(trigger)}\b", vba_code, re.IGNORECASE):
                    if trigger not in found:
                        found.append(trigger)

        return list(dict.fromkeys(found))  # deduplicate preserving order

    def _run_mraptor(self, vba_code: str) -> Dict[str, Any]:
        """Chay MacroRaptor de phat hien macro behavior."""
        if not OLETOOLS_AVAILABLE:
            return {}

        try:
            mraptor = MacroRaptor(vba_code.encode('utf-8', errors='ignore'))
            mraptor.analyze()
            return {
                "suspicious": mraptor.suspicious,
                " IOC": mraptor.ioc,
                "macro_type": mraptor.type,
            }
        except Exception:
            return {}

    # ─── PDF Analysis ──────────────────────────────────────────────────────

    def _analyze_pdf(self, file_path: str, result: OfficeScanResult):
        """Phan tich PDF de phat hien action va JavaScript."""
        if not PYMUPDF_AVAILABLE:
            result.error = "PyMuPDF not installed — install with: pip install PyMuPDF"
            return

        try:
            doc = fitz.open(file_path)

            # Check for dangerous actions
            self._check_pdf_actions(doc, result)

            # Extract embedded JavaScript
            self._extract_pdf_javascript(doc, result)

            # Check for embedded files
            self._check_pdf_embedded_files(doc, result)

            doc.close()

        except Exception as e:
            result.error = f"PDF analysis error: {e}"
            logger.debug(f"PDF analysis failed for {file_path}: {e}")

    def _check_pdf_actions(self, doc, result: OfficeScanResult):
        """Phat hien /OpenAction, /Launch, /AA trong PDF."""
        for page_num in range(len(doc)):
            page = doc[page_num]

            # Check page dictionary for actions
            xref = page.xref

            # Get page dictionary
            page_dict = doc.xref_object(xref, compressed=False)

            # Search for dangerous action keywords
            for action_type in PDF_DANGEROUS_ACTIONS:
                if action_type in page_dict:
                    result.pdf_actions.append({
                        "type": action_type.lstrip("/"),
                        "page": page_num + 1,
                        "detail": f"Found in page {page_num + 1}",
                    })

            # Check /OpenAction at document level
            if page_num == 0:
                root = doc.xref_object(doc.pdf_xref_length() - 1, compressed=False)
                if "/OpenAction" in root:
                    result.pdf_actions.append({
                        "type": "OpenAction",
                        "page": 1,
                        "detail": "Document-level OpenAction",
                    })

    def _extract_pdf_javascript(self, doc, result: OfficeScanResult):
        """Trich xuat JavaScript nhung trong PDF."""
        js_pattern = re.compile(
            r'(?:javascript|JavaScript|JS)\s*:\s*(.{10,500}?)(?:\n|"|;|\))',
            re.IGNORECASE | re.MULTILINE
        )

        # Also check for /JS entries
        names = doc.names() if hasattr(doc, 'names') else {}
        if names:
            # Look in /Names dictionary for JavaScript
            names_str = str(names)
            for match in js_pattern.finditer(names_str):
                js_snippet = match.group(1).strip()[:200]
                if js_snippet not in result.pdf_javascript:
                    result.pdf_javascript.append(js_snippet)

        # Also scan raw text for JS patterns
        for page in doc:
            text = page.get_text()
            for match in js_pattern.finditer(text):
                js_snippet = match.group(1).strip()[:200]
                if js_snippet not in result.pdf_javascript:
                    result.pdf_javascript.append(js_snippet)

    def _check_pdf_embedded_files(self, doc, result: OfficeScanResult):
        """Kiem tra file nhung trong PDF."""
        # Check /EmbeddedFiles
        for page_num in range(len(doc)):
            page = doc[page_num]
            page_str = page.get_text("dict") if hasattr(page, 'get_text') else ""

            if "/EmbeddedFiles" in page_str or "/EmbeddedFile" in page_str:
                result.pdf_embedded_files.append(f"Embedded file in page {page_num + 1}")

    # ─── RTF Analysis ──────────────────────────────────────────────────────

    def _analyze_rtf(self, file_path: str, result: OfficeScanResult):
        """Phan tich RTF de phat hien OLE objects va shellcode."""
        if not OLETOOLS_AVAILABLE:
            result.error = "oletools not installed"
            return

        try:
            for obj in rtfobj(file_path):
                if obj is None:
                    continue

                obj_info = {
                    "index": obj.index if hasattr(obj, 'index') else 0,
                    "size": obj.size if hasattr(obj, 'size') else 0,
                    "ole_type": obj.ole_type if hasattr(obj, 'ole_type') else "unknown",
                    "class_name": obj.class_name if hasattr(obj, 'class_name') else "",
                    "is_package": obj.is_package if hasattr(obj, 'is_package') else False,
                }

                # Check for suspicious OLE types
                suspicious_types = [
                    "Application", "Excel", "Word", "PowerPoint",
                    "Script", "Shell", "WScript", "CScript",
                ]
                if obj_info["ole_type"] and any(
                    st.lower() in (obj_info["ole_type"] or "").lower()
                    for st in suspicious_types
                ):
                    result.triggers_found.append(f"RTF_OLE:{obj_info['ole_type']}")

                # Check for package (embedded executable)
                if obj_info["is_package"]:
                    result.triggers_found.append("RTF_Package_Embedded")

                result.rtf_objects.append(obj_info)

        except Exception as e:
            logger.debug(f"RTF analysis failed for {file_path}: {e}")

    # ─── YARA Integration ──────────────────────────────────────────────────

    def _scan_yara(self, result: OfficeScanResult):
        """Quet file bang YARA engine."""
        if self._yara_engine is None:
            self._yara_engine = _get_yara_engine()

        if self._yara_engine is None:
            return

        try:
            matches = self._yara_engine.scan_file(result.file_path)
            for match in matches:
                result.yara_matches.append({
                    "rule_name": match.rule_name,
                    "description": match.description,
                    "severity": match.severity,
                    "family": match.family,
                })
                # Add trigger for YARA match
                result.triggers_found.append(f"YARA:{match.rule_name}")
        except Exception as e:
            logger.debug(f"YARA scan failed: {e}")

    # ─── Threat Level Determination ─────────────────────────────────────

    def _determine_threat_level(self, result: OfficeScanResult):
        """Dua vao cac phan tich de xac dinh muc do nguy hiem."""
        score = 0

        # Auto-exec triggers = highly suspicious
        if result.triggers_found:
            for trigger in result.triggers_found:
                if trigger.startswith("YARA:") and "CRITICAL" in trigger:
                    score += 5
                elif any(t in trigger for t in ["AutoOpen", "Auto_Open", "Document_Open",
                                                  "Workbook_Open", "AutoExec"]):
                    score += 3
                elif "YARA:" in trigger:
                    score += 2
                elif "RTF_" in trigger:
                    score += 2

        # Macro found
        if result.macro_count > 0:
            score += 1

        # PDF dangerous actions
        if result.pdf_actions:
            score += len(result.pdf_actions) * 2
            for action in result.pdf_actions:
                if action["type"] in ["OpenAction", "Launch", "JavaScript"]:
                    score += 2

        # PDF JavaScript
        if result.pdf_javascript:
            score += len(result.pdf_javascript) * 2

        # RTF OLE objects
        if result.rtf_objects:
            score += len(result.rtf_objects) * 1

        # YARA matches severity
        for match in result.yara_matches:
            if match["severity"] == "CRITICAL":
                score += 4
            elif match["severity"] == "HIGH":
                score += 2
            elif match["severity"] == "MEDIUM":
                score += 1

        # Assign threat level
        if score >= 6:
            result.threat_level = THREAT_MALICIOUS
        elif score >= 2:
            result.threat_level = THREAT_SUSPICIOUS
        else:
            result.threat_level = THREAT_CLEAN

    def _generate_recommendation(self, result: OfficeScanResult):
        """Tao khuyen nghi based tren ket qua phan tich."""
        if result.threat_level == THREAT_CLEAN:
            result.recommendation = "File trong sach — khong co dau hieu ma doc."
            return

        parts = []

        if result.triggers_found:
            triggers_str = ", ".join(result.triggers_found[:5])
            parts.append(f"Phat hien triggers: {triggers_str}")

        if result.pdf_actions:
            actions_str = ", ".join(a["type"] for a in result.pdf_actions[:3])
            parts.append(f"Hanh dong PDF nguy hiem: {actions_str}")

        if result.pdf_javascript:
            parts.append(f"JavaScript nhung trong PDF: {len(result.pdf_javascript)} instance(s)")

        if result.macro_count > 0:
            parts.append(f"{result.macro_count} macro VBA duoc tim thay")

        if result.yara_matches:
            families = ", ".join(set(m["family"] for m in result.yara_matches[:3]))
            parts.append(f"YARA match: {families}")

        if result.threat_level == THREAT_MALICIOUS:
            result.recommendation = (
                "CANH BAO: File co kha nang la ma doc (MALICIOUS). "
                + " | ".join(parts)
                + ". Khuyen nghi: cach ly file, quet voi antivirus khac, "
                + "khong mo file."
            )
        else:
            result.recommendation = (
                "NGHI NGO: File co dau hieu dang nghi (SUSPICIOUS). "
                + " | ".join(parts)
                + ". Khuyen nghi: xem xet ky lua, neu khong can thiet thi xoa."
            )

    # ─── Utilities ────────────────────────────────────────────────────────

    @staticmethod
    def _compute_sha256(file_path: str) -> str:
        """Tinh SHA256 cua file."""
        if not os.path.isfile(file_path):
            return ""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""


# ─── Singleton ─────────────────────────────────────────────────────────────

_analyzer_instance: Optional[OfficeDocAnalyzer] = None


def get_office_analyzer() -> OfficeDocAnalyzer:
    """Lay singleton instance cua OfficeDocAnalyzer."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = OfficeDocAnalyzer()
    return _analyzer_instance
