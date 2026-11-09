from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import streamlit as st
from forensic_utils import (
    get_image_details, register_hash, compare_registered_hash,
    create_pdf_report
)

st.set_page_config(page_title="ImageGuard | Image Forensics", page_icon="🔎", layout="wide")

st.title("🔎 ImageGuard")
st.subheader("Digital Forensics Tool for Image Analysis")
st.caption("Analyze image properties, inspect available metadata, calculate SHA-256, and export a report.")

with st.sidebar:
    st.header("Case details")
    case_id = st.text_input("Case ID", value="CASE-001", help="Use the same Case ID to compare a file with its registered baseline.")
    investigator = st.text_input("Investigator name", value="")
    notes = st.text_area("Investigator notes", placeholder="Record the purpose of analysis, source of image, and relevant observations.")
    st.divider()
    st.caption("For coursework and authorized analysis only. Do not alter the original evidence file.")

uploaded = st.file_uploader(
    "Upload an image for examination",
    type=["jpg", "jpeg", "png", "tif", "tiff", "bmp", "webp", "gif"],
    help="The tool reads the uploaded bytes and does not intentionally modify the source file."
)

if not uploaded:
    st.info("Upload a sample image to begin. Try a JPEG from your camera and a PNG screenshot to compare metadata.")
    st.markdown("""
    **Available modules**
    - Image details and preview
    - EXIF metadata and GPS-tag listing (when present)
    - SHA-256 file-integrity hash
    - Basic file-format and decoding checks
    - Local baseline hash registration and verification
    - PDF and JSON report downloads
    """)
    st.stop()

# Read the exact uploaded bytes once; analysis functions do not write over the source.
image_bytes = uploaded.getvalue()
filename = os.path.basename(uploaded.name)
analysis = get_image_details(image_bytes, filename)
analysis["analysis_time_utc"] = datetime.now(timezone.utc).isoformat()
comparison = compare_registered_hash(case_id, filename, analysis["sha256"])

st.success(f"Loaded: {filename}")
left, right = st.columns([1, 1])
with left:
    st.image(image_bytes, caption=filename, use_container_width=True)
with right:
    st.markdown("### Image summary")
    a, b = st.columns(2)
    a.metric("File size", f"{len(image_bytes):,} bytes")
    b.metric("Detected format", analysis["detected_format"])
    a.metric("Width", str(analysis["width"] or "Unavailable"))
    b.metric("Height", str(analysis["height"] or "Unavailable"))
    st.markdown("**SHA-256 hash**")
    st.code(analysis["sha256"], language=None)
    st.caption("The hash is calculated from the exact uploaded file bytes.")

tab1, tab2, tab3, tab4 = st.tabs(["Image Details", "EXIF Metadata", "Forensic Checks", "Evidence & Reports"])

with tab1:
    st.markdown("### File properties")
    properties = {
        "Filename": analysis["filename"],
        "Extension": analysis["extension"],
        "Detected format": analysis["detected_format"],
        "File size": analysis["file_size_human"],
        "Dimensions": f"{analysis['width']} × {analysis['height']}" if analysis["width"] else "Unavailable",
        "Color mode": analysis["mode"] or "Unavailable",
        "Frame count": analysis["frame_count"] if analysis["frame_count"] is not None else "Unavailable",
        "Analysis time (UTC)": analysis["analysis_time_utc"],
    }
    st.table([{"Property": k, "Value": v} for k, v in properties.items()])
    if "decode_error" in analysis:
        st.error(f"Image decoding issue: {analysis['decode_error']}")

with tab2:
    st.markdown("### EXIF metadata")
    st.caption("Metadata can be missing, edited, or removed by ordinary software. Values are not independently authenticated.")
    exif = analysis.get("exif", {})
    if exif:
        st.dataframe(
            [{"Tag": k, "Value": v} for k, v in exif.items()],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No readable EXIF tags were found.")
    gps = analysis.get("gps", {})
    st.markdown("### GPS-related tags")
    if gps:
        st.dataframe([{"Tag": k, "Value": v} for k, v in gps.items()], use_container_width=True, hide_index=True)
    else:
        st.info("No GPS-related EXIF tags were found. This does not mean the image has no location history elsewhere.")

with tab3:
    st.markdown("### Automated checks")
    for check in analysis["checks"]:
        if check["status"] == "PASS":
            st.success(f"**{check['name']} — {check['status']}**\n\n{check['detail']}")
        elif check["status"] == "REVIEW":
            st.warning(f"**{check['name']} — {check['status']}**\n\n{check['detail']}")
        else:
            st.info(f"**{check['name']} — {check['status']}**\n\n{check['detail']}")
    st.markdown("### Registered hash comparison")
    status = comparison["status"]
    if status == "MATCH":
        st.success(f"**{status}:** {comparison['detail']}")
    elif status == "MISMATCH":
        st.error(f"**{status}:** {comparison['detail']}")
    else:
        st.info(f"**{status}:** {comparison['detail']}")

with tab4:
    st.markdown("### Evidence integrity")
    st.write("Register a baseline hash when you first examine the evidence. Later, upload the same named file under the same Case ID to compare it against the saved hash.")
    st.warning("The registry is a local coursework convenience, not a tamper-proof evidence store. Protect it and retain independent copies for any formal workflow.")
    if st.button("Register current SHA-256 as baseline", type="primary"):
        if not case_id.strip():
            st.error("Enter a Case ID in the sidebar first.")
        else:
            register_hash(case_id, filename, analysis["sha256"], notes)
            st.success("Baseline hash saved to reports/evidence_registry.json.")
            st.rerun()

    st.markdown("### Export analysis")
    report_payload = {
        "tool": "ImageGuard",
        "case_id": case_id,
        "investigator": investigator,
        "analysis_time_utc": analysis["analysis_time_utc"],
        "notes": notes,
        "image_analysis": analysis,
        "registered_hash_comparison": comparison,
        "limitations": [
            "This tool does not prove authenticity or detect all image manipulation.",
            "A hash match confirms byte-for-byte consistency with the saved baseline only.",
            "Missing EXIF metadata is not proof of tampering."
        ]
    }
    safe_case = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (case_id or "case"))
    pdf_bytes = create_pdf_report(analysis, case_id, investigator, notes, comparison)
    json_bytes = json.dumps(report_payload, indent=2, ensure_ascii=False).encode("utf-8")
    c1, c2 = st.columns(2)
    with c1:
        st.download_button(
            "Download PDF report",
            data=pdf_bytes,
            file_name=f"ImageGuard_{safe_case}_report.pdf",
            mime="application/pdf",
            use_container_width=True
        )
    with c2:
        st.download_button(
            "Download JSON report",
            data=json_bytes,
            file_name=f"ImageGuard_{safe_case}_report.json",
            mime="application/json",
            use_container_width=True
        )
    st.caption("Download the reports and retain them with your project evidence. The report records findings and limitations.")

st.divider()
st.caption("ImageGuard is an educational prototype, not a certified forensic suite. Follow your institution's evidence-handling procedures.")
