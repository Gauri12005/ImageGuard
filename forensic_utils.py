"""Core image-forensics helpers for ImageGuard.

This educational tool performs basic image metadata and integrity checks.
It does not prove image authenticity or detect all forms of manipulation.
"""
from __future__ import annotations

import hashlib
import io
import json
import mimetypes
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import exifread
from PIL import Image, UnidentifiedImageError
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

REGISTRY_PATH = Path(__file__).parent / "reports" / "evidence_registry.json"

EXTENSION_FORMATS = {
    ".jpg": {"JPEG"}, ".jpeg": {"JPEG"}, ".png": {"PNG"},
    ".tif": {"TIFF"}, ".tiff": {"TIFF"}, ".bmp": {"BMP"},
    ".webp": {"WEBP"}, ".gif": {"GIF"},
}

def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 digest of the exact supplied file bytes."""
    return hashlib.sha256(data).hexdigest()

def _safe_tag_value(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "[unreadable value]"

def extract_exif(data: bytes) -> dict[str, str]:
    """Extract readable EXIF tags. Empty result means no readable tags found."""
    result: dict[str, str] = {}
    try:
        tags = exifread.process_file(io.BytesIO(data), details=False, strict=True)
        for key, value in tags.items():
            if key in {"JPEGThumbnail", "TIFFThumbnail"}:
                continue
            result[str(key)] = _safe_tag_value(value)
    except Exception as exc:
        result["_EXIF_READ_NOTE"] = f"EXIF could not be fully read: {type(exc).__name__}"
    return result

def get_image_details(data: bytes, filename: str) -> dict[str, Any]:
    """Read image properties without changing the supplied bytes."""
    details: dict[str, Any] = {
        "filename": os.path.basename(filename),
        "file_size_bytes": len(data),
        "file_size_human": f"{len(data):,} bytes",
        "sha256": sha256_bytes(data),
        "extension": Path(filename).suffix.lower() or "(none)",
        "detected_format": "Unknown",
        "width": None,
        "height": None,
        "mode": None,
        "frame_count": None,
        "exif": {},
        "gps": {},
        "checks": [],
    }

    try:
        with Image.open(io.BytesIO(data)) as im:
            details["detected_format"] = im.format or "Unknown"
            details["width"], details["height"] = im.size
            details["mode"] = im.mode
            details["frame_count"] = getattr(im, "n_frames", 1)
            # Force decode to catch many malformed/truncated image cases.
            im.verify()
        # verify() invalidates the image object; reopen and load separately.
        with Image.open(io.BytesIO(data)) as im2:
            im2.load()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        details["decode_error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        details["decode_error"] = f"{type(exc).__name__}: {exc}"

    details["exif"] = extract_exif(data)
    details["gps"] = {
        key: value for key, value in details["exif"].items()
        if "GPS" in key.upper()
    }

    checks = []
    detected = details["detected_format"]
    expected = EXTENSION_FORMATS.get(details["extension"])
    if detected == "Unknown":
        checks.append({
            "name": "Image decoding",
            "status": "FAIL",
            "detail": "The file could not be identified as a supported image or could not be decoded."
        })
    else:
        checks.append({
            "name": "Image decoding",
            "status": "PASS",
            "detail": f"The file was identified as {detected} and decoded by Pillow."
        })

    if expected and detected != "Unknown" and detected not in expected:
        checks.append({
            "name": "Extension / format consistency",
            "status": "REVIEW",
            "detail": f"Filename extension is {details['extension']}, but detected format is {detected}."
        })
    elif detected != "Unknown":
        checks.append({
            "name": "Extension / format consistency",
            "status": "PASS",
            "detail": "No mismatch was identified for the filename extension and detected format."
        })
    else:
        checks.append({
            "name": "Extension / format consistency",
            "status": "REVIEW",
            "detail": "Could not compare extension with a reliable detected image format."
        })

    readable_exif = bool(details["exif"]) and not (
        len(details["exif"]) == 1 and "_EXIF_READ_NOTE" in details["exif"]
    )
    checks.append({
        "name": "EXIF metadata availability",
        "status": "INFO" if readable_exif else "INFO",
        "detail": (
            f"{len(details['exif'])} EXIF tag(s)/note(s) were read. Metadata may be absent or removed."
            if readable_exif else
            "No readable EXIF tags were found. This is common and is not proof of tampering."
        )
    })
    details["checks"] = checks
    return details

def load_registry() -> dict[str, Any]:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not REGISTRY_PATH.exists():
        return {}
    try:
        with REGISTRY_PATH.open("r", encoding="utf-8") as f:
            value = json.load(f)
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}

def save_registry(registry: dict[str, Any]) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = REGISTRY_PATH.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2, ensure_ascii=False)
    temp_path.replace(REGISTRY_PATH)

def register_hash(case_id: str, filename: str, digest: str, notes: str = "") -> None:
    """Record a baseline hash in a local JSON registry."""
    registry = load_registry()
    key = f"{case_id.strip()}::{os.path.basename(filename)}"
    registry[key] = {
        "case_id": case_id.strip(),
        "filename": os.path.basename(filename),
        "sha256": digest,
        "registered_at_utc": datetime.now(timezone.utc).isoformat(),
        "notes": notes.strip(),
    }
    save_registry(registry)

def compare_registered_hash(case_id: str, filename: str, digest: str) -> dict[str, str]:
    registry = load_registry()
    key = f"{case_id.strip()}::{os.path.basename(filename)}"
    saved = registry.get(key)
    if not saved:
        return {
            "status": "NOT REGISTERED",
            "detail": "No baseline hash was found for this case ID and filename. Register the baseline first."
        }
    if saved.get("sha256") == digest:
        return {
            "status": "MATCH",
            "detail": f"Current hash matches the baseline registered at {saved.get('registered_at_utc', 'unknown time')}."
        }
    return {
        "status": "MISMATCH",
        "detail": "Current hash differs from the saved baseline. The file bytes differ; investigate further."
    }

def create_pdf_report(analysis: dict[str, Any], case_id: str, investigator: str,
                      notes: str, hash_comparison: dict[str, str] | None = None) -> bytes:
    """Create a portable PDF report in memory."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=18*mm, leftMargin=18*mm,
        topMargin=16*mm, bottomMargin=16*mm
    )
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("ImageGuard — Digital Image Forensics Report", styles["Title"]))
    story.append(Paragraph("Educational image analysis and evidence-integrity record", styles["Italic"]))
    story.append(Spacer(1, 8))
    generated = datetime.now(timezone.utc).isoformat()
    basic_rows = [
        ["Field", "Value"],
        ["Case ID", case_id or "Not supplied"],
        ["Investigator", investigator or "Not supplied"],
        ["Report generated (UTC)", generated],
        ["Filename", str(analysis.get("filename", ""))],
        ["File size", str(analysis.get("file_size_human", ""))],
        ["Detected format", str(analysis.get("detected_format", "Unknown"))],
        ["Dimensions", f"{analysis.get('width')} × {analysis.get('height')}" if analysis.get("width") else "Unavailable"],
        ["Color mode", str(analysis.get("mode", "Unavailable"))],
        ["Frames", str(analysis.get("frame_count", "Unavailable"))],
        ["SHA-256", str(analysis.get("sha256", ""))],
    ]
    table = Table(basic_rows, colWidths=[43*mm, 125*mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#23395d")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("WORDWRAP", (0,0), (-1,-1), True),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Forensic checks", styles["Heading2"]))
    check_rows = [["Check", "Status", "Details"]]
    for item in analysis.get("checks", []):
        check_rows.append([item.get("name", ""), item.get("status", ""), item.get("detail", "")])
    if hash_comparison:
        check_rows.append(["Registered hash comparison", hash_comparison.get("status", ""),
                           hash_comparison.get("detail", "")])
    check_table = Table(check_rows, colWidths=[42*mm, 25*mm, 101*mm], repeatRows=1)
    check_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#23395d")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.35, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 7.5),
        ("LEFTPADDING", (0,0), (-1,-1), 5),
        ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(check_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("EXIF metadata", styles["Heading2"]))
    exif_rows = [["Tag", "Value"]]
    exif = analysis.get("exif", {})
    if exif:
        for key, value in list(exif.items())[:250]:
            exif_rows.append([str(key), str(value)])
    else:
        exif_rows.append(["Metadata", "No readable EXIF metadata found"])
    exif_table = Table(exif_rows, colWidths=[55*mm, 113*mm], repeatRows=1)
    exif_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#23395d")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.3, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(exif_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Investigator notes", styles["Heading2"]))
    story.append(Paragraph((notes or "No notes supplied.").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>"), styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "Limitations: This report documents results from this tool; it does not establish that an image is authentic, "
        "that its metadata is truthful, or that no manipulation occurred. Hash matching confirms byte-for-byte "
        "consistency only against the recorded baseline. Preserve the original evidence and document acquisition "
        "and handling separately for formal investigations.",
        styles["BodyText"]
    ))
    doc.build(story)
    return buffer.getvalue()
