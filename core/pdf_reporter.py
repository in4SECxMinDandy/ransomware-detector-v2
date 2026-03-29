"""
pdf_reporter.py — Extended Office Report Module
==========================================
Generate PDF reports for Office document scan results.
"""

import os
from datetime import datetime
from typing import List

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)

# ─── Colors ──────────────────────────────────────────────────────────────
C_RED = HexColor("#F38BA8")
C_GREEN = HexColor("#A6E3A1")
C_YELLOW = HexColor("#F9E2AF")
C_BLUE = HexColor("#89B4FA")
C_PURPLE = HexColor("#CBA6F7")
C_BG = HexColor("#1E1E2E")
C_SURFACE = HexColor("#313244")
C_TEXT = HexColor("#CDD6F4")
C_TEXT_DIM = HexColor("#A6ADC8")
C_BORDER = HexColor("#45475A")


def export_office_report(results: List, output_dir: str) -> str:
    """
    Generate a PDF report for Office document scan results.

    Args:
        results: List of OfficeScanResult objects
        output_dir: Output directory path

    Returns:
        Path to generated PDF file
    """

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"office_scan_report_{timestamp}.pdf"
    filepath = os.path.join(output_dir, filename)

    os.makedirs(output_dir, exist_ok=True)

    # Create PDF
    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    story = []

    # ─── Title ──────────────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=C_BLUE,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=C_TEXT_DIM,
        spaceAfter=20,
    )

    story.append(Paragraph("Office Document Security Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Files Scanned: {len(results)}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    story.append(Spacer(1, 12))

    # ─── Summary ─────────────────────────────────────────────────────────
    malicious = sum(1 for r in results if r.threat_level == "MALICIOUS")
    suspicious = sum(1 for r in results if r.threat_level == "SUSPICIOUS")
    clean = sum(1 for r in results if r.threat_level == "CLEAN")

    summary_style = ParagraphStyle("SummaryTitle", parent=styles["Heading2"],
                                  textColor=C_BLUE, fontSize=14, spaceAfter=8)
    story.append(Paragraph("Scan Summary", summary_style))

    summary_data = [
        ["Threat Level", "Count", "Status"],
        ["MALICIOUS", str(malicious), "Action Required" if malicious > 0 else "None"],
        ["SUSPICIOUS", str(suspicious), "Review Recommended" if suspicious > 0 else "None"],
        ["CLEAN", str(clean), "No Threat Detected"],
        ["TOTAL", str(len(results)), ""],
    ]

    summary_table = Table(summary_data, colWidths=[2 * inch, 1.5 * inch, 3 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_SURFACE),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_TEXT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 1), (-1, 1), C_RED),
        ("TEXTCOLOR", (0, 2), (-1, 2), C_YELLOW),
        ("TEXTCOLOR", (0, 3), (-1, 3), C_GREEN),
        ("BACKGROUND", (0, -1), (-1, -1), C_SURFACE),
        ("TEXTCOLOR", (0, -1), (-1, -1), C_TEXT),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_SURFACE]),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # ─── Detailed Results ─────────────────────────────────────────────────
    detail_style = ParagraphStyle("DetailTitle", parent=styles["Heading2"],
                                  textColor=C_BLUE, fontSize=14, spaceAfter=8)
    story.append(Paragraph("Detailed Analysis", detail_style))

    code_style = ParagraphStyle(
        "Code",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7,
        textColor=C_TEXT_DIM,
        backColor=C_SURFACE,
        leftIndent=10,
        rightIndent=10,
        spaceBefore=4,
        spaceAfter=4,
    )

    threat_style_normal = ParagraphStyle("ThreatNormal", parent=styles["Normal"],
                                          textColor=C_GREEN, fontSize=10)
    threat_style_susp = ParagraphStyle("ThreatSusp", parent=styles["Normal"],
                                         textColor=C_YELLOW, fontSize=10)
    threat_style_mal = ParagraphStyle("ThreatMal", parent=styles["Normal"],
                                        textColor=C_RED, fontSize=10)

    for i, result in enumerate(results):
        if result.threat_level == "MALICIOUS":
            ts = threat_style_mal
            bg = HexColor("#3D1E1E")
        elif result.threat_level == "SUSPICIOUS":
            ts = threat_style_susp
            bg = HexColor("#3D3A1E")
        else:
            ts = threat_style_normal
            bg = C_BG

        # File header
        file_data = [
            [Paragraph(f"<b>{result.filename}</b>", ts)],
            [Paragraph(f"Path: {result.file_path}", ParagraphStyle("p", parent=styles["Normal"], fontSize=8, textColor=C_TEXT_DIM))],
            [Paragraph(f"Size: {result.file_size / 1024:.1f} KB | "
                      f"SHA256: {result.sha256[:32]}...",
                      ParagraphStyle("p", parent=styles["Normal"], fontSize=8, textColor=C_TEXT_DIM))],
        ]

        file_table = Table(file_data, colWidths=[6.5 * inch])
        file_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("ROUNDEDCORNERS", [4]),
        ]))

        story.append(file_table)
        story.append(Spacer(1, 4))

        # Analysis details
        details = []
        if result.triggers_found:
            details.append(f"<b>Auto-Exec Triggers:</b> {', '.join(result.triggers_found[:5])}")
        if result.macro_count > 0:
            details.append(f"<b>Macros Found:</b> {result.macro_count}")
        if result.pdf_actions:
            actions_str = ", ".join([a.get("type", "?") for a in result.pdf_actions[:3]])
            details.append(f"<b>PDF Actions:</b> {actions_str}")
        if result.pdf_javascript:
            details.append(f"<b>JavaScript:</b> {len(result.pdf_javascript)} instance(s)")
        if result.yara_matches:
            yara_str = ", ".join([m.get("rule_name", "?") for m in result.yara_matches[:3]])
            details.append(f"<b>YARA Matches:</b> {yara_str}")

        if details:
            detail_text = " | ".join(details)
            detail_style = ParagraphStyle("Detail", parent=styles["Normal"],
                                        fontSize=9, textColor=C_TEXT_DIM,
                                        leftIndent=10)
            story.append(Paragraph(detail_text, detail_style))
            story.append(Spacer(1, 4))

        # Macro code snippet
        if result.macro_code_snippet:
            code_text = result.macro_code_snippet[:500] + ("..." if len(result.macro_code_snippet) > 500 else "")
            story.append(Paragraph("<b>Macro Code Preview:</b>", ParagraphStyle("Label", parent=styles["Normal"], fontSize=9, textColor=C_TEXT)))
            story.append(Paragraph(code_text, code_style))

        # Recommendation
        if result.recommendation:
            rec_style = ParagraphStyle("Rec", parent=styles["Normal"], fontSize=9,
                                      textColor=C_YELLOW if result.threat_level != "CLEAN" else C_TEXT_DIM)
            story.append(Paragraph(f"<b>Recommendation:</b> {result.recommendation}", rec_style))

        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
        story.append(Spacer(1, 8))

        # Page break every 3 results
        if (i + 1) % 3 == 0 and i < len(results) - 1:
            story.append(PageBreak())

    # Build PDF
    doc.build(story)
    return filepath
