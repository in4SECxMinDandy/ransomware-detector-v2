"""
training_source_registry.py
===========================
Curated registry of official/research-grade sample sources for PE-only
training workflows.
"""

from __future__ import annotations

from typing import Dict, List, Optional


SCALE_PRESETS: Dict[str, Dict[str, int | str]] = {
    "smoke": {
        "name": "Smoke test",
        "target_per_class": 100,
        "prepare_limit": 100,
    },
    "pilot": {
        "name": "Pilot",
        "target_per_class": 1000,
        "prepare_limit": 1000,
    },
    "production": {
        "name": "Production",
        "target_per_class": 5000,
        "prepare_limit": 5000,
    },
}


SOURCE_REGISTRY: List[Dict[str, object]] = [
    {
        "id": "napierone",
        "name": "NapierOne Mixed File Dataset",
        "url": "https://registry.opendata.aws/napierone/",
        "kind": "safe",
        "pe_only": False,
        "official": True,
        "access_mode": "aws_registry",
        "source_type": "benign_corpus",
        "default_subset_strategy": "pilot_1k_pe",
        "estimated_size_gb": 10.0,
        "download_risk": "low",
        "license_notes": "Public research dataset; review registry terms before redistribution.",
        "safety_notes": "Mixed corpus. Filter to PE-only and re-scan before treating samples as benign.",
        "prepare_hint": "Copy selected PE files into datasets/sources/safe/napierone before prepare.",
        "keywords": ["napierone", "aws", "mixed", "files", "exe", "dll", "benign", "safe"],
        "summary": "Large public mixed-file corpus with many benign file types, including PE files to filter into SAFE training sets.",
        "notes": "Best public benign/mixed source to mine EXE/DLL samples for PE-only training.",
        "next_step_template": "Acquire a PE-only subset, place it under datasets/sources/safe/napierone, then run prepare-training-source.",
    },
    {
        "id": "govdocs1",
        "name": "Govdocs1",
        "url": "https://digitalcorpora.org/corpora/file-corpora/files/",
        "kind": "safe",
        "pe_only": False,
        "official": True,
        "access_mode": "html_instructions",
        "source_type": "benign_corpus",
        "default_subset_strategy": "pilot_1k_pe",
        "estimated_size_gb": 5.0,
        "download_risk": "medium",
        "license_notes": "Freely redistributable corpus from Digital Corpora.",
        "safety_notes": "Useful as a secondary benign source only after re-scanning and PE-only filtering.",
        "prepare_hint": "Use as a supplementary source under datasets/sources/safe/govdocs1.",
        "keywords": ["govdocs", "digital corpora", "documents", "mixed", "files", "safe", "benign"],
        "summary": "Large freely redistributable corpus from Digital Corpora.",
        "notes": "Useful as a secondary benign source, but re-scan and filter before using it as ground-truth SAFE.",
        "next_step_template": "Download a manageable subset manually, filter PE files, then prepare.",
    },
    {
        "id": "filetypes1",
        "name": "FILETYPES1",
        "url": "https://digitalcorpora.org/2014/02/05/announcing-new-file-type-sample-files/",
        "kind": "safe",
        "pe_only": False,
        "official": True,
        "access_mode": "html_instructions",
        "source_type": "benign_corpus",
        "default_subset_strategy": "smoke_100_pe",
        "estimated_size_gb": 1.0,
        "download_risk": "low",
        "license_notes": "Public Digital Corpora sample set.",
        "safety_notes": "Good bootstrap source for benign PE examples.",
        "prepare_hint": "Store under datasets/sources/safe/filetypes1 before prepare.",
        "keywords": ["filetypes1", "digital corpora", "sample files", "exe", "dll", "safe"],
        "summary": "Smaller public file-type sample set including EXE and DLL examples.",
        "notes": "Good for bootstrapping a compact benign PE folder.",
        "next_step_template": "Download manually, place files under datasets/sources/safe/filetypes1, then prepare.",
    },
    {
        "id": "trusted-vendors",
        "name": "Trusted Vendor Installers",
        "url": "",
        "kind": "safe",
        "pe_only": True,
        "official": True,
        "access_mode": "manual",
        "source_type": "vendor_bundle",
        "default_subset_strategy": "pilot_1k_pe",
        "estimated_size_gb": 2.0,
        "download_risk": "low",
        "license_notes": "Use binaries you legally obtained from official vendor sites.",
        "safety_notes": "Preferred supplemental benign PE source.",
        "prepare_hint": "Collect installers/executables in datasets/sources/safe/trusted-vendors.",
        "keywords": ["vendor", "installer", "sysinternals", "python", "7zip", "git", "vlc", "libreoffice", "safe"],
        "summary": "Collect benign PE files from trusted software vendors you legally own or download from official sites.",
        "notes": "Recommended supplement for SAFE PE samples: Sysinternals, 7-Zip, Git for Windows, Python installers, Notepad++, VLC, LibreOffice.",
        "next_step_template": "Copy official vendor installers/executables into datasets/sources/safe/trusted-vendors, then prepare.",
    },
    {
        "id": "sorel20m-github",
        "name": "SOREL-20M GitHub",
        "url": "https://github.com/sophos/SOREL-20M",
        "kind": "encrypted",
        "pe_only": True,
        "official": True,
        "access_mode": "html_instructions",
        "source_type": "malware_corpus",
        "default_subset_strategy": "pilot_1k_pe",
        "estimated_size_gb": 8.0,
        "download_risk": "high",
        "license_notes": "Research-grade disarmed malware; follow source terms and local policy.",
        "safety_notes": "Use only approved disarmed subsets in isolated storage.",
        "prepare_hint": "Place approved disarmed PE samples under datasets/sources/encrypted/sorel20m-github.",
        "keywords": ["sorel", "sophos", "malware", "disarmed", "pe", "encrypted"],
        "summary": "Research-grade malware dataset documentation with disarmed samples and metadata.",
        "notes": "Recommended public source for PE-only malware/disarmed training samples.",
        "next_step_template": "Acquire an approved disarmed subset and place it under datasets/sources/encrypted/sorel20m-github, then prepare.",
    },
    {
        "id": "sorel20m-aws",
        "name": "SOREL-20M AWS Open Data",
        "url": "https://registry.opendata.aws/sorel-20m/",
        "kind": "encrypted",
        "pe_only": True,
        "official": True,
        "access_mode": "aws_registry",
        "source_type": "malware_corpus",
        "default_subset_strategy": "pilot_1k_pe",
        "estimated_size_gb": 78.0,
        "download_risk": "high",
        "license_notes": "Research-grade disarmed malware corpus; review terms and approval requirements.",
        "safety_notes": "Very large corpus. Use only approved PE-only subsets.",
        "prepare_hint": "Store approved subset under datasets/sources/encrypted/sorel20m-aws.",
        "keywords": ["sorel", "aws", "open data", "malware", "disarmed", "pe", "encrypted"],
        "summary": "AWS Open Data registry entry for SOREL-20M.",
        "notes": "Very large corpus; use subsets only. Best when you already know how to select a manageable PE-only slice.",
        "next_step_template": "Acquire a subset via approved AWS workflow, then place it under datasets/sources/encrypted/sorel20m-aws and prepare.",
    },
]


def get_scale_preset(scale: str) -> Dict[str, int | str]:
    return SCALE_PRESETS.get(scale, SCALE_PRESETS["pilot"])


def get_source_by_id(source_id: str) -> Optional[Dict[str, object]]:
    for source in SOURCE_REGISTRY:
        if str(source.get("id")) == source_id:
            return source
    return None


def search_training_sources(
    query: str = "",
    kind: Optional[str] = None,
    pe_only: Optional[bool] = None,
) -> List[Dict[str, object]]:
    query_tokens = [token.strip().lower() for token in query.split() if token.strip()]
    results: List[Dict[str, object]] = []

    for source in SOURCE_REGISTRY:
        source_kind = str(source.get("kind", "")).lower()
        if kind and kind.lower() != "both" and source_kind != kind.lower():
            continue
        if pe_only is not None and bool(source.get("pe_only")) != pe_only:
            continue

        haystack = " ".join(
            [
                str(source.get("id", "")),
                str(source.get("name", "")),
                str(source.get("summary", "")),
                str(source.get("notes", "")),
                str(source.get("source_type", "")),
                str(source.get("access_mode", "")),
                " ".join(str(keyword) for keyword in (source.get("keywords") or [])),  # type: ignore[union-attr]
            ]
        ).lower()

        if query_tokens and not all(token in haystack for token in query_tokens):
            continue
        results.append(source)

    return results


def render_training_sources(
    query: str = "",
    kind: Optional[str] = None,
    pe_only: Optional[bool] = None,
) -> str:
    results = search_training_sources(query=query, kind=kind, pe_only=pe_only)
    if not results:
        return "No matching training sources found."

    lines = []
    for source in results:
        lines.append(
            f"- {source['name']} [{source['kind']}] "
            f"(access={source['access_mode']}, risk={source['download_risk']})"
        )
        url = str(source.get("url", "")).strip()
        if url:
            lines.append(f"  URL: {url}")
        lines.append(f"  Summary: {source['summary']}")
        lines.append(f"  Notes: {source['notes']}")
    return "\n".join(lines)
