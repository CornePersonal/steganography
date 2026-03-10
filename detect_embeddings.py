"""
Stego Embedding Detector — Multi-engine steganography detection.

Combines multiple analysis engines to detect AND classify hidden data:
  1. Chi-square statistical analysis (LSB detection in spatial domain)
  2. JPEG DCT histogram analysis (detects Jsteg/F5-style DCT embedding)
  3. stegano LSB reveal (tries standard LSB message extraction)
  4. EXIF/metadata anomaly detection (hidden fields, comments, thumbnails)
  5. File structure analysis (appended data, dual headers, EOF markers)
  6. stegoveritas (extraction: trailing data, carving, steghide, brute LSB)

PyQt6 GUI with drag-and-drop, or CLI mode.

Usage (GUI):  python detect_embeddings.py
Usage (CLI):  python detect_embeddings.py --cli <image_or_folder> [--out results] [--deep]

Dependencies:
    pip install stegoveritas python-magic-bin PyQt6 stegano numpy pillow exifread
"""

import os
import struct
import subprocess
import sys
import json
import math
from pathlib import Path

import numpy as np
from PIL import Image
import exifread

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QFileDialog, QMessageBox,
    QProgressBar, QGroupBox, QCheckBox, QScrollArea, QFrame,
    QTextEdit, QSizePolicy,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPixmap, QDragEnterEvent, QDropEvent


IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff', '.tif', '.webp'}
IMAGE_FILTER = "Images (*.png *.jpg *.jpeg *.bmp *.gif *.tiff *.tif *.webp)"

# ═══════════════════════════════════════════════════════════════════════════
# Theme (matches StegoCrypt v2 dark theme)
# ═══════════════════════════════════════════════════════════════════════════
DARK_BG = "#12121c"
SURFACE = "#1e1e2e"
ACCENT = "#7c3aed"
ACCENT_HOVER = "#6d28d9"
TEXT = "#e0e0e0"
RED = "#ef4444"
GREEN = "#22c55e"
YELLOW = "#eab308"

APP_STYLE = f"""
QMainWindow, QWidget {{
    background: {DARK_BG};
    color: {TEXT};
    font-family: 'Segoe UI', sans-serif;
}}
QScrollBar:vertical {{
    background: {SURFACE};
    width: 10px;
    border-radius: 5px;
}}
QScrollBar::handle:vertical {{
    background: #444;
    border-radius: 5px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QMessageBox {{
    background: {SURFACE};
    color: {TEXT};
}}
QMessageBox QPushButton {{
    background: {ACCENT};
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 16px;
    min-width: 70px;
}}
"""

GROUP_STYLE = f"""
QGroupBox {{
    color: {TEXT};
    border: 1px solid #333;
    border-radius: 6px;
    margin-top: 8px;
    font-size: 12px;
    font-weight: bold;
    padding-top: 6px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #aaa;
}}
"""

INPUT_STYLE = f"""
QLineEdit {{
    background: #2a2a3e;
    color: {TEXT};
    border: 1px solid #444;
    border-radius: 5px;
    padding: 6px 10px;
    font-size: 13px;
}}
QLineEdit:focus {{
    border-color: {ACCENT};
}}
"""

BTN_PRIMARY_STYLE = f"""
QPushButton {{
    background: {ACCENT};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 10px 20px;
    font-size: 14px;
    font-weight: bold;
}}
QPushButton:hover {{
    background: {ACCENT_HOVER};
}}
QPushButton:disabled {{
    background: #444;
    color: #888;
}}
"""

BTN_SECONDARY_STYLE = f"""
QPushButton {{
    background: #2a2a3e;
    color: {TEXT};
    border: 1px solid #555;
    border-radius: 5px;
    padding: 6px 14px;
    font-size: 12px;
}}
QPushButton:hover {{
    background: #363650;
    border-color: {ACCENT};
}}
"""

BTN_DANGER_STYLE = f"""
QPushButton {{
    background: #3b1a1a;
    color: {RED};
    border: 1px solid #5c2020;
    border-radius: 5px;
    padding: 6px 14px;
    font-size: 12px;
}}
QPushButton:hover {{
    background: #4d2020;
    border-color: {RED};
}}
"""

PROGRESS_STYLE = f"""
QProgressBar {{
    background: #2a2a3e;
    border: 1px solid #444;
    border-radius: 4px;
    height: 14px;
    text-align: center;
    color: white;
    font-size: 10px;
}}
QProgressBar::chunk {{
    background: {ACCENT};
    border-radius: 4px;
}}
"""

LOG_STYLE = f"""
QTextEdit {{
    background: #0d0d14;
    color: #b0b0cc;
    border: 1px solid #333;
    border-radius: 5px;
    padding: 6px;
    font-size: 12px;
    font-family: 'Consolas', 'Courier New', monospace;
}}
"""


# ═══════════════════════════════════════════════════════════════════════════
# Engine 1: Chi-square LSB detection (spatial domain)
# ═══════════════════════════════════════════════════════════════════════════

def chi_square_lsb(image_path: str) -> dict:
    """Statistical chi-square test on pixel LSBs.

    Compares the distribution of pixel value pairs (2k, 2k+1) — in a natural
    image these pairs have unequal counts, but LSB embedding equalizes them.
    Returns a probability that LSB embedding is present.
    """
    result = {"engine": "chi_square", "detected": False, "confidence": 0.0,
              "technique": "", "details": ""}
    try:
        img = Image.open(image_path).convert("RGB")
        pixels = np.array(img).flatten()

        # Count occurrences of each byte value
        counts = np.bincount(pixels, minlength=256).astype(np.float64)

        # Pair adjacent values: (0,1), (2,3), ..., (254,255)
        chi2 = 0.0
        pairs = 0
        for k in range(0, 256, 2):
            expected = (counts[k] + counts[k + 1]) / 2.0
            if expected > 0:
                chi2 += ((counts[k] - expected) ** 2) / expected
                chi2 += ((counts[k + 1] - expected) ** 2) / expected
                pairs += 1

        # Degrees of freedom = number of pairs - 1
        dof = max(pairs - 1, 1)

        # Approximate p-value using the normal approximation of chi-square
        # For large dof: (chi2 - dof) / sqrt(2*dof) ~ N(0,1)
        z = (chi2 - dof) / math.sqrt(2 * dof) if dof > 0 else 0

        # Low chi-square (near dof) means pairs are suspiciously equal → LSB embedding
        # z << 0 means chi2 << dof → very uniform pairs → strong LSB signal
        if z < -3.0:
            confidence = min(1.0, (-z - 3.0) / 5.0 + 0.7)
            result["detected"] = True
            result["confidence"] = round(confidence, 3)
            result["technique"] = "LSB replacement (spatial)"
            result["details"] = (
                f"Chi-square z-score: {z:.2f} (strongly uniform pixel pairs). "
                f"This indicates LSB replacement steganography."
            )
        elif z < -1.5:
            confidence = round(0.3 + (-z - 1.5) / 3.0, 3)
            result["confidence"] = confidence
            result["details"] = (
                f"Chi-square z-score: {z:.2f} — mildly suspicious pixel pair distribution."
            )
        else:
            result["details"] = f"Chi-square z-score: {z:.2f} — normal distribution."

    except Exception as e:
        result["details"] = f"Error: {e}"
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Engine 2: JPEG DCT histogram analysis
# ═══════════════════════════════════════════════════════════════════════════

def jpeg_dct_analysis(image_path: str) -> dict:
    """Detect DCT-domain steganography (Jsteg, F5) by analyzing raw JPEG data.

    Jsteg replaces the LSB of non-zero, non-one DCT coefficients, which
    equalizes the counts of coefficient pairs (2k, 2k+1). We scan the raw
    JPEG scan data for this signature.
    """
    result = {"engine": "jpeg_dct", "detected": False, "confidence": 0.0,
              "technique": "", "details": ""}

    if Path(image_path).suffix.lower() not in ('.jpg', '.jpeg'):
        result["details"] = "Not a JPEG — skipped."
        return result

    try:
        with open(image_path, "rb") as f:
            data = f.read()

        # Find SOS marker (Start of Scan) — DCT data follows it
        sos_idx = data.find(b'\xff\xda')
        if sos_idx == -1:
            result["details"] = "No SOS marker found."
            return result

        # Scan segment header length
        header_len = struct.unpack('>H', data[sos_idx + 2:sos_idx + 4])[0]
        scan_data = data[sos_idx + 2 + header_len:]

        # Undo byte stuffing (0xFF 0x00 → 0xFF)
        unstuffed = scan_data.replace(b'\xff\x00', b'\xff')

        # Count byte value pairs in the scan data
        if len(unstuffed) < 100:
            result["details"] = "Scan data too short for analysis."
            return result

        byte_counts = np.bincount(
            np.frombuffer(unstuffed[:min(len(unstuffed), 500_000)], dtype=np.uint8),
            minlength=256,
        ).astype(np.float64)

        chi2 = 0.0
        pairs = 0
        for k in range(0, 256, 2):
            expected = (byte_counts[k] + byte_counts[k + 1]) / 2.0
            if expected > 5:
                chi2 += ((byte_counts[k] - expected) ** 2) / expected
                chi2 += ((byte_counts[k + 1] - expected) ** 2) / expected
                pairs += 1

        dof = max(pairs - 1, 1)
        z = (chi2 - dof) / math.sqrt(2 * dof) if dof > 0 else 0

        if z < -2.5:
            confidence = min(1.0, (-z - 2.5) / 4.0 + 0.6)
            result["detected"] = True
            result["confidence"] = round(confidence, 3)
            result["technique"] = "DCT coefficient manipulation (Jsteg/F5-style)"
            result["details"] = (
                f"DCT scan data z-score: {z:.2f}. Suspiciously uniform coefficient "
                f"pairs suggest DCT-domain LSB steganography."
            )
        elif z < -1.0:
            result["confidence"] = round(0.2 + (-z - 1.0) / 4.0, 3)
            result["details"] = f"DCT z-score: {z:.2f} — mildly suspicious."
        else:
            result["details"] = f"DCT z-score: {z:.2f} — normal."

    except Exception as e:
        result["details"] = f"Error: {e}"
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Engine 3: stegano LSB reveal
# ═══════════════════════════════════════════════════════════════════════════

def stegano_lsb_check(image_path: str) -> dict:
    """Try to extract an LSB-hidden message using the stegano library."""
    result = {"engine": "stegano_lsb", "detected": False, "confidence": 0.0,
              "technique": "", "details": ""}

    if Path(image_path).suffix.lower() not in ('.png', '.bmp', '.tiff', '.tif'):
        result["details"] = "stegano LSB only supports lossless formats — skipped."
        return result

    try:
        from stegano.lsb import reveal
        msg = reveal(image_path)
        if msg and len(msg) > 0:
            # Check if it looks like real text (printable ASCII ratio)
            printable = sum(1 for c in msg[:200] if 32 <= ord(c) <= 126 or c in '\n\r\t')
            ratio = printable / min(len(msg), 200)

            if ratio > 0.7:
                result["detected"] = True
                result["confidence"] = round(min(1.0, 0.6 + ratio * 0.3), 3)
                result["technique"] = "LSB encoding (stegano-compatible)"
                preview = msg[:120].replace('\n', ' ')
                result["details"] = (
                    f"Extracted {len(msg)} chars via standard LSB. "
                    f"Preview: \"{preview}{'...' if len(msg) > 120 else ''}\""
                )
            else:
                result["details"] = (
                    f"LSB extraction returned {len(msg)} chars but mostly non-printable "
                    f"({ratio:.0%} printable) — likely not a text message."
                )
                result["confidence"] = round(ratio * 0.3, 3)
        else:
            result["details"] = "No LSB message found via stegano."
    except Exception as e:
        err = str(e)
        if "index" in err.lower() or "out of range" in err.lower():
            result["details"] = "No stegano-format LSB message present."
        else:
            result["details"] = f"stegano error: {err}"
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Engine 4: EXIF / metadata anomaly detection
# ═══════════════════════════════════════════════════════════════════════════

SUSPICIOUS_EXIF_TAGS = {
    "Image ImageDescription", "EXIF UserComment", "Image XPComment",
    "Image XPSubject", "Image XPKeywords", "Image Copyright",
    "EXIF MakerNote", "Image Software",
}

def exif_metadata_check(image_path: str) -> dict:
    """Scan EXIF metadata for hidden data, suspicious fields, or large comments."""
    result = {"engine": "exif_metadata", "detected": False, "confidence": 0.0,
              "technique": "", "details": ""}
    findings = []

    try:
        with open(image_path, "rb") as f:
            tags = exifread.process_file(f, details=True)

        if not tags:
            result["details"] = "No EXIF metadata present."
            return result

        for tag_name, tag_val in tags.items():
            val_str = str(tag_val)

            # Check suspicious tags for hidden content
            if tag_name in SUSPICIOUS_EXIF_TAGS and len(val_str) > 50:
                findings.append(
                    f"Large {tag_name} ({len(val_str)} chars): "
                    f"\"{val_str[:80]}{'...' if len(val_str) > 80 else ''}\""
                )

            # Check for base64-encoded data in any field
            if len(val_str) > 100:
                alpha_count = sum(1 for c in val_str if c.isalnum() or c in '+/=')
                if alpha_count / len(val_str) > 0.95:
                    findings.append(
                        f"Possible base64 in {tag_name} ({len(val_str)} chars)"
                    )

            # Check for embedded scripts or suspicious strings
            lower_val = val_str.lower()
            for suspicious in ("<?php", "<script", "eval(", "base64_decode",
                               "powershell", "cmd.exe"):
                if suspicious in lower_val:
                    findings.append(f"Suspicious content in {tag_name}: '{suspicious}'")

        # Check thumbnail size (can hide data in oversized thumbnails)
        if "JPEGThumbnail" in tags:
            thumb = tags["JPEGThumbnail"]
            if hasattr(thumb, '__len__') and len(thumb) > 20000:
                findings.append(f"Oversized JPEG thumbnail ({len(thumb)} bytes)")

        if findings:
            result["detected"] = True
            result["confidence"] = round(min(1.0, 0.4 + 0.15 * len(findings)), 3)
            result["technique"] = "EXIF metadata embedding"
            result["details"] = " | ".join(findings)
        else:
            result["details"] = f"EXIF present ({len(tags)} tags) — no anomalies."

    except Exception as e:
        result["details"] = f"EXIF read error: {e}"
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Engine 5: File structure analysis
# ═══════════════════════════════════════════════════════════════════════════

# Known file signatures
FILE_SIGS = {
    b'\x89PNG':   "PNG",
    b'\xff\xd8':  "JPEG",
    b'GIF8':      "GIF",
    b'BM':        "BMP",
    b'PK':        "ZIP/Office",
    b'Rar':       "RAR",
    b'7z':        "7z",
    b'%PDF':      "PDF",
    b'\x1f\x8b':  "gzip",
}

def file_structure_check(image_path: str) -> dict:
    """Check for appended data, embedded files, and format anomalies."""
    result = {"engine": "file_structure", "detected": False, "confidence": 0.0,
              "technique": "", "details": ""}
    findings = []

    try:
        with open(image_path, "rb") as f:
            data = f.read()

        file_size = len(data)
        ext = Path(image_path).suffix.lower()

        # --- JPEG: find end-of-image marker (FFD9), check for trailing data ---
        if ext in ('.jpg', '.jpeg') and data[:2] == b'\xff\xd8':
            eoi = data.rfind(b'\xff\xd9')
            if eoi != -1 and eoi + 2 < file_size:
                trailing = file_size - (eoi + 2)
                findings.append(
                    f"JPEG has {trailing:,} bytes after EOI marker (appended data)"
                )
                # Check what's in the trailing data
                trail = data[eoi + 2:]
                for sig, fmt in FILE_SIGS.items():
                    if trail[:len(sig)] == sig:
                        findings.append(f"Trailing data starts with {fmt} signature")
                        break

        # --- PNG: find IEND chunk, check for trailing data ---
        elif ext == '.png' and data[:4] == b'\x89PNG':
            iend = data.find(b'IEND')
            if iend != -1:
                # IEND chunk: 4 bytes length + 4 bytes "IEND" + 4 bytes CRC = after iend+8
                end_pos = iend + 8  # skip IEND + CRC
                if end_pos < file_size:
                    trailing = file_size - end_pos
                    findings.append(
                        f"PNG has {trailing:,} bytes after IEND chunk"
                    )
                    trail = data[end_pos:]
                    for sig, fmt in FILE_SIGS.items():
                        if trail[:len(sig)] == sig:
                            findings.append(f"Appended data has {fmt} signature")
                            break

        # --- Search for embedded file signatures after the first 16 bytes ---
        embedded = []
        for sig, fmt in FILE_SIGS.items():
            # Search starting from byte 16 (skip the image's own header)
            pos = data.find(sig, 16)
            while pos != -1:
                # Don't flag the image's own format
                if not (pos < 8):
                    embedded.append(f"{fmt} signature at offset {pos:#x}")
                pos = data.find(sig, pos + 1)

        if embedded:
            findings.append(f"Embedded file signatures: {', '.join(embedded[:5])}")

        if findings:
            result["detected"] = True
            result["confidence"] = round(min(1.0, 0.5 + 0.15 * len(findings)), 3)
            result["technique"] = "File append / embedded files"
            result["details"] = " | ".join(findings)
        else:
            result["details"] = f"File structure clean ({file_size:,} bytes)."

    except Exception as e:
        result["details"] = f"Error: {e}"
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Engine 6: stegoveritas (extraction-based)
# ═══════════════════════════════════════════════════════════════════════════

def run_stegoveritas(image_path: str, output_dir: str,
                     password: str | None = None, deep: bool = False) -> dict:
    """Run stegoveritas CLI and parse output."""
    result = {"engine": "stegoveritas", "detected": False, "confidence": 0.0,
              "technique": "", "details": "", "extracted_files": []}

    image_name = Path(image_path).stem
    img_out = os.path.join(output_dir, image_name)
    os.makedirs(img_out, exist_ok=True)

    cmd = ["stegoveritas", image_path, "-out", img_out, "-meta", "-trailing"]
    if deep:
        cmd.extend(["-bruteLSB", "-imageTransform", "-colorMap",
                     "-exif", "-xmp", "-carve"])
    if password:
        cmd.extend(["-password", password])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        result["details"] = "stegoveritas not found — install with: pip install stegoveritas"
        return result

    stdout, stderr = proc.stdout, proc.stderr
    detail_lines = []
    if stdout.strip():
        detail_lines.append(stdout.strip())

    found_types = []
    checks = {
        "trailing": ("trailing_data", "Trailing / appended data extraction"),
        "keepers": ("carved_files", "Binwalk file carving"),
        "LSB":     ("lsb_data", "LSB brute-force extraction"),
        "steghide": ("steghide", "Steghide payload extraction"),
    }
    for folder, (indicator, desc) in checks.items():
        path = os.path.join(img_out, folder)
        if os.path.isdir(path):
            files = os.listdir(path)
            if files:
                result["detected"] = True
                found_types.append(desc)
                result["extracted_files"].extend(
                    [os.path.join(path, f) for f in files]
                )
                detail_lines.append(f"{indicator}: {files}")

    if found_types:
        result["technique"] = "; ".join(found_types)
        result["confidence"] = round(min(1.0, 0.5 + 0.2 * len(found_types)), 3)

    if stderr.strip():
        detail_lines.append(f"[stderr] {stderr.strip()}")

    result["details"] = "\n".join(detail_lines)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Multi-engine orchestrator
# ═══════════════════════════════════════════════════════════════════════════

def scan_image(image_path: str, output_dir: str,
               password: str | None = None, deep: bool = False,
               log_fn=None) -> dict:
    """Run all detection engines on a single image and aggregate results."""

    def _log(msg):
        if log_fn:
            log_fn(msg)

    findings = {
        "file": image_path,
        "has_embedding": False,
        "confidence": 0.0,
        "techniques_detected": [],
        "engines": [],
        "extracted_files": [],
        "summary": "",
    }

    engines = [
        ("Chi-Square LSB", lambda: chi_square_lsb(image_path)),
        ("JPEG DCT Analysis", lambda: jpeg_dct_analysis(image_path)),
        ("Stegano LSB Reveal", lambda: stegano_lsb_check(image_path)),
        ("EXIF Metadata", lambda: exif_metadata_check(image_path)),
        ("File Structure", lambda: file_structure_check(image_path)),
        ("StegoVeritas", lambda: run_stegoveritas(image_path, output_dir, password, deep)),
    ]

    for name, engine_fn in engines:
        _log(f"    [{name}] running...")
        try:
            r = engine_fn()
            findings["engines"].append(r)

            status = "DETECTED" if r["detected"] else "clean"
            extra = f" — {r['technique']}" if r.get("technique") else ""
            _log(f"    [{name}] {status}{extra}")
            if r.get("details"):
                _log(f"      {r['details'][:200]}")

            if r["detected"]:
                findings["has_embedding"] = True
                if r.get("technique"):
                    findings["techniques_detected"].append(r["technique"])
                findings["confidence"] = max(findings["confidence"], r["confidence"])

            if r.get("extracted_files"):
                findings["extracted_files"].extend(r["extracted_files"])

        except Exception as e:
            _log(f"    [{name}] error: {e}")
            findings["engines"].append({
                "engine": name, "detected": False, "confidence": 0.0,
                "technique": "", "details": f"Error: {e}",
            })

    # Build summary
    if findings["has_embedding"]:
        techs = ", ".join(dict.fromkeys(findings["techniques_detected"]))
        findings["summary"] = (
            f"EMBEDDING DETECTED (confidence: {findings['confidence']:.0%}). "
            f"Techniques: {techs or 'unknown'}."
        )
    else:
        findings["summary"] = "No steganographic embedding detected."

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Worker thread (runs scans off the UI thread)
# ═══════════════════════════════════════════════════════════════════════════

class ScanWorker(QThread):
    progress = pyqtSignal(int, int)          # (current_index, total)
    log = pyqtSignal(str)                    # log line
    image_done = pyqtSignal(dict)            # single finding
    finished_all = pyqtSignal(list)          # all findings

    def __init__(self, image_paths, output_dir, password, deep):
        super().__init__()
        self.image_paths = image_paths
        self.output_dir = output_dir
        self.password = password
        self.deep = deep
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        results = []
        total = len(self.image_paths)
        for i, img in enumerate(self.image_paths):
            if self._cancel:
                self.log.emit("[Cancelled]")
                break
            self.progress.emit(i, total)
            self.log.emit(f"\n[{i+1}/{total}] Scanning: {Path(img).name}")
            try:
                findings = scan_image(
                    img, self.output_dir, self.password, self.deep,
                    log_fn=self.log.emit,
                )
                results.append(findings)
                self.image_done.emit(findings)
                self.log.emit(f"  >> {findings['summary']}")
            except Exception as e:
                self.log.emit(f"  !! Error: {e}")
                results.append({
                    "file": img, "has_embedding": False, "confidence": 0.0,
                    "techniques_detected": [], "engines": [],
                    "extracted_files": [], "summary": f"Error: {e}",
                })
        self.progress.emit(total, total)
        self.finished_all.emit(results)


# ═══════════════════════════════════════════════════════════════════════════
# Image drop zone widget
# ═══════════════════════════════════════════════════════════════════════════

class DropZone(QLabel):
    files_dropped = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.setText("Drop images here\nor click to browse")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.setMinimumHeight(140)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._update_style(False)

    def _update_style(self, hover: bool):
        border = ACCENT if hover else "#555"
        color = "#bbb" if hover else "#888"
        self.setStyleSheet(f"""
            QLabel {{
                border: 2px dashed {border};
                border-radius: 10px;
                background: {SURFACE};
                color: {color};
                font-size: 14px;
            }}
        """)

    def mousePressEvent(self, event):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select Images", "", IMAGE_FILTER
        )
        if paths:
            self.files_dropped.emit(paths)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._update_style(True)

    def dragLeaveEvent(self, event):
        self._update_style(False)

    def dropEvent(self, event: QDropEvent):
        self._update_style(False)
        urls = event.mimeData().urls()
        paths = []
        for u in urls:
            p = u.toLocalFile()
            if os.path.isfile(p) and Path(p).suffix.lower() in IMAGE_EXTENSIONS:
                paths.append(p)
            elif os.path.isdir(p):
                for f in sorted(Path(p).iterdir()):
                    if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS:
                        paths.append(str(f))
        if paths:
            self.files_dropped.emit(paths)


# ═══════════════════════════════════════════════════════════════════════════
# Image list item widget
# ═══════════════════════════════════════════════════════════════════════════

class ImageCard(QFrame):
    remove_clicked = pyqtSignal(str)

    def __init__(self, image_path: str):
        super().__init__()
        self.image_path = image_path
        self.setFixedHeight(68)
        self.setStyleSheet(f"""
            QFrame {{
                background: {SURFACE};
                border: 1px solid #333;
                border-radius: 6px;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(10)

        # Thumbnail
        thumb = QLabel()
        px = QPixmap(image_path).scaled(
            52, 52,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        thumb.setPixmap(px)
        thumb.setFixedSize(56, 56)
        thumb.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(thumb)

        # Info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        name_label = QLabel(Path(image_path).name)
        name_label.setStyleSheet(f"color:{TEXT}; font-size:13px; font-weight:bold; border:none;")
        info_layout.addWidget(name_label)

        size_kb = os.path.getsize(image_path) / 1024
        size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.2f} MB"
        size_label = QLabel(size_str)
        size_label.setStyleSheet("color:#888; font-size:11px; border:none;")
        info_layout.addWidget(size_label)
        layout.addLayout(info_layout, 1)

        # Status badge
        self.status_label = QLabel("Pending")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setFixedWidth(160)
        self._set_status("pending")
        layout.addWidget(self.status_label)

        # Remove button
        remove_btn = QPushButton("✕")
        remove_btn.setFixedSize(28, 28)
        remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: #666;
                border: 1px solid #444;
                border-radius: 14px;
                font-size: 13px;
            }}
            QPushButton:hover {{
                color: {RED};
                border-color: {RED};
                background: #2a1515;
            }}
        """)
        remove_btn.clicked.connect(lambda: self.remove_clicked.emit(self.image_path))
        layout.addWidget(remove_btn)

    def _set_status(self, status: str, text: str = ""):
        styles = {
            "pending":  (f"color:#888; background:#2a2a3e; border:1px solid #444;"
                         f" border-radius:10px; font-size:11px; padding:3px 8px;"),
            "scanning": (f"color:{YELLOW}; background:#2a2a1e; border:1px solid {YELLOW};"
                         f" border-radius:10px; font-size:11px; padding:3px 8px;"),
            "clean":    (f"color:{GREEN}; background:#1a2e1a; border:1px solid {GREEN};"
                         f" border-radius:10px; font-size:11px; padding:3px 8px;"),
            "detected": (f"color:{RED}; background:#2e1a1a; border:1px solid {RED};"
                         f" border-radius:10px; font-size:11px; padding:3px 8px;"),
            "error":    (f"color:{YELLOW}; background:#2e2a1a; border:1px solid {YELLOW};"
                         f" border-radius:10px; font-size:11px; padding:3px 8px;"),
        }
        labels = {
            "pending": "Pending",
            "scanning": "Scanning...",
            "clean": "Clean",
            "detected": "Embedding!",
            "error": "Error",
        }
        self.status_label.setStyleSheet(styles.get(status, styles["pending"]))
        self.status_label.setText(text or labels.get(status, status))

    def mark_scanning(self):
        self._set_status("scanning")

    def mark_result(self, findings: dict):
        if findings["has_embedding"]:
            techs = findings.get("techniques_detected", [])
            conf = findings.get("confidence", 0)
            label = f"{conf:.0%}"
            if techs:
                short = techs[0][:25] + ("..." if len(techs[0]) > 25 else "")
                if len(techs) > 1:
                    short += f" +{len(techs)-1}"
                label = short
            self._set_status("detected", label)
        else:
            self._set_status("clean")

    def mark_error(self, msg: str):
        self._set_status("error", "Error")


# ═══════════════════════════════════════════════════════════════════════════
# Main Window
# ═══════════════════════════════════════════════════════════════════════════

class DetectorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Stego Detector — Embedding Scanner")
        self.setMinimumSize(680, 720)
        self.resize(750, 850)
        self.setStyleSheet(APP_STYLE)

        self._image_paths: list[str] = []
        self._cards: dict[str, ImageCard] = {}
        self._worker: ScanWorker | None = None
        self._findings: list[dict] = []

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 14, 18, 14)
        root.setSpacing(12)

        # ── Title ──
        title = QLabel("Stego Embedding Detector")
        title.setStyleSheet(f"color:{TEXT}; font-size:20px; font-weight:bold;")
        subtitle = QLabel("Drag & drop images to scan for hidden data")
        subtitle.setStyleSheet("color:#888; font-size:12px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        # ── Drop zone ──
        self.drop_zone = DropZone()
        self.drop_zone.files_dropped.connect(self._add_images)
        root.addWidget(self.drop_zone)

        # ── Image list ──
        list_group = QGroupBox("Images to Scan")
        list_group.setStyleSheet(GROUP_STYLE)
        list_inner = QVBoxLayout(list_group)
        list_inner.setContentsMargins(8, 16, 8, 8)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ border: none; background: {DARK_BG}; }}")
        self.list_widget = QWidget()
        self.list_layout = QVBoxLayout(self.list_widget)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_layout.setSpacing(4)
        self.list_layout.addStretch()
        scroll.setWidget(self.list_widget)
        list_inner.addWidget(scroll)

        self.count_label = QLabel("0 images loaded")
        self.count_label.setStyleSheet("color:#888; font-size:11px;")
        list_inner.addWidget(self.count_label)

        root.addWidget(list_group, 1)

        # ── Options row ──
        opts_group = QGroupBox("Options")
        opts_group.setStyleSheet(GROUP_STYLE)
        opts_layout = QHBoxLayout(opts_group)
        opts_layout.setContentsMargins(12, 18, 12, 10)

        self.deep_check = QCheckBox("Deep Scan")
        self.deep_check.setStyleSheet(f"color:{TEXT}; font-size:12px;")
        self.deep_check.setToolTip("LSB brute-force, color maps, carving, image transforms")
        opts_layout.addWidget(self.deep_check)

        opts_layout.addSpacing(20)
        pw_label = QLabel("Password:")
        pw_label.setStyleSheet(f"color:#aaa; font-size:12px;")
        opts_layout.addWidget(pw_label)
        self.pw_edit = QLineEdit()
        self.pw_edit.setPlaceholderText("Optional — for steghide")
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_edit.setFixedWidth(180)
        self.pw_edit.setStyleSheet(INPUT_STYLE)
        opts_layout.addWidget(self.pw_edit)

        opts_layout.addStretch()

        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.setStyleSheet(BTN_DANGER_STYLE)
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.clicked.connect(self._clear_all)
        opts_layout.addWidget(self.clear_btn)

        root.addWidget(opts_group)

        # ── Progress ──
        self.progress = QProgressBar()
        self.progress.setStyleSheet(PROGRESS_STYLE)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setFormat("Ready")
        root.addWidget(self.progress)

        # ── Buttons ──
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.scan_btn = QPushButton("Scan Images")
        self.scan_btn.setStyleSheet(BTN_PRIMARY_STYLE)
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.clicked.connect(self._start_scan)
        btn_row.addWidget(self.scan_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setStyleSheet(BTN_SECONDARY_STYLE)
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_scan)
        btn_row.addWidget(self.cancel_btn)

        self.export_btn = QPushButton("Export Report")
        self.export_btn.setStyleSheet(BTN_SECONDARY_STYLE)
        self.export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export_report)
        btn_row.addWidget(self.export_btn)

        root.addLayout(btn_row)

        # ── Log output ──
        log_group = QGroupBox("Scan Log")
        log_group.setStyleSheet(GROUP_STYLE)
        log_inner = QVBoxLayout(log_group)
        log_inner.setContentsMargins(8, 16, 8, 8)
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setStyleSheet(LOG_STYLE)
        self.log_edit.setMinimumHeight(100)
        log_inner.addWidget(self.log_edit)
        root.addWidget(log_group)

    # ── Slots ──

    def _add_images(self, paths: list[str]):
        for p in paths:
            if p not in self._cards:
                self._image_paths.append(p)
                card = ImageCard(p)
                card.remove_clicked.connect(self._remove_image)
                self._cards[p] = card
                self.list_layout.insertWidget(self.list_layout.count() - 1, card)
        self._update_count()

    def _remove_image(self, path: str):
        if path in self._cards:
            card = self._cards.pop(path)
            self._image_paths.remove(path)
            self.list_layout.removeWidget(card)
            card.deleteLater()
        self._update_count()

    def _clear_all(self):
        for p in list(self._cards.keys()):
            self._remove_image(p)
        self._findings.clear()
        self.log_edit.clear()
        self.progress.setValue(0)
        self.progress.setFormat("Ready")
        self.export_btn.setEnabled(False)

    def _update_count(self):
        n = len(self._image_paths)
        self.count_label.setText(f"{n} image{'s' if n != 1 else ''} loaded")
        self.scan_btn.setEnabled(n > 0)

    def _start_scan(self):
        if not self._image_paths:
            return

        self._findings.clear()
        self.log_edit.clear()
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)

        # Reset card statuses
        for card in self._cards.values():
            card._set_status("pending")

        out_dir = os.path.join(os.getcwd(), "results")
        os.makedirs(out_dir, exist_ok=True)

        pw = self.pw_edit.text().strip() or None
        deep = self.deep_check.isChecked()

        self._worker = ScanWorker(list(self._image_paths), out_dir, pw, deep)
        self._worker.progress.connect(self._on_progress)
        self._worker.log.connect(self._on_log)
        self._worker.image_done.connect(self._on_image_done)
        self._worker.finished_all.connect(self._on_finished)
        self._worker.start()

    def _cancel_scan(self):
        if self._worker:
            self._worker.cancel()
            self.cancel_btn.setEnabled(False)

    def _on_progress(self, current: int, total: int):
        pct = int(current / total * 100) if total else 0
        self.progress.setValue(pct)
        self.progress.setFormat(f"{current}/{total} — {pct}%")
        # Mark current card as scanning
        if current < len(self._image_paths):
            path = self._image_paths[current]
            if path in self._cards:
                self._cards[path].mark_scanning()

    def _on_log(self, text: str):
        self.log_edit.append(text)

    def _on_image_done(self, findings: dict):
        self._findings.append(findings)
        path = findings["file"]
        if path in self._cards:
            self._cards[path].mark_result(findings)

    def _on_finished(self, all_findings: list):
        self._findings = all_findings
        self.scan_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)

        detected = sum(1 for f in all_findings if f["has_embedding"])
        total = len(all_findings)
        self.progress.setValue(100)
        self.progress.setFormat(f"Done — {detected}/{total} with embeddings")

        self._on_log("")
        self._on_log(f"{'='*50}")
        self._on_log(f"  Scan Complete: {total} image(s)")
        self._on_log(f"  Embeddings found: {detected}")
        self._on_log(f"  Clean: {total - detected}")
        if detected:
            self._on_log("")
            for f in all_findings:
                if f["has_embedding"]:
                    techs = ", ".join(f.get("techniques_detected", ["unknown"]))
                    self._on_log(
                        f"  !! {Path(f['file']).name} — "
                        f"confidence {f.get('confidence', 0):.0%} — {techs}"
                    )
        self._on_log(f"{'='*50}")

        if detected:
            QMessageBox.warning(
                self, "Embeddings Detected",
                f"Found steganographic indicators in {detected} of {total} image(s).\n\n"
                "Check the scan log for details.",
            )
        else:
            QMessageBox.information(
                self, "Scan Complete",
                f"All {total} image(s) appear clean. No embeddings detected.",
            )

    def _export_report(self):
        if not self._findings:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "detection_report.json",
            "JSON (*.json)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(self._findings, fp, indent=2)
            QMessageBox.information(self, "Exported",
                                    f"Report saved to:\n{path}")


# ═══════════════════════════════════════════════════════════════════════════
# CLI entry point (kept for scripting use)
# ═══════════════════════════════════════════════════════════════════════════

def cli_main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Detect steganographic embeddings in images (multi-engine)."
    )
    parser.add_argument("target", help="Image file or directory of images to scan.")
    parser.add_argument("--out", default="results",
                        help="Output directory (default: results).")
    parser.add_argument("--password", default=None,
                        help="Password for steghide extraction.")
    parser.add_argument("--deep", action="store_true",
                        help="Deep analysis (LSB brute-force, carving, transforms).")
    args = parser.parse_args()

    target = Path(args.target)
    if target.is_file():
        images = [str(target)]
    elif target.is_dir():
        images = [str(f) for f in sorted(target.iterdir())
                  if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS]
    else:
        print(f"[!] Target not found: {args.target}")
        sys.exit(1)

    if not images:
        print("[!] No images found.")
        sys.exit(1)

    print(f"[*] Found {len(images)} image(s) to scan.")
    os.makedirs(args.out, exist_ok=True)

    all_findings = []
    for i, img in enumerate(images, 1):
        print(f"\n[{i}/{len(images)}] Scanning: {img}")
        findings = scan_image(img, args.out, args.password, args.deep,
                              log_fn=lambda m: print(m))
        all_findings.append(findings)
        print(f"  >> {findings['summary']}")

    # Summary
    detected = [f for f in all_findings if f["has_embedding"]]
    clean = [f for f in all_findings if not f["has_embedding"]]
    print(f"\n{'='*60}")
    print(f"  Scanned: {len(all_findings)} | Detected: {len(detected)} | Clean: {len(clean)}")
    for f in detected:
        techs = ", ".join(f.get("techniques_detected", ["unknown"]))
        print(f"  [!] {f['file']} — {f.get('confidence', 0):.0%} — {techs}")
    print(f"{'='*60}")

    report = os.path.join(args.out, "detection_report.json")
    with open(report, "w", encoding="utf-8") as fp:
        json.dump(all_findings, fp, indent=2, default=str)
    print(f"[*] Report saved: {report}")


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        sys.argv.pop(1)  # remove --cli so argparse sees the rest
        cli_main()
    elif len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        # Legacy: direct path argument → CLI mode
        cli_main()
    else:
        app = QApplication(sys.argv)
        app.setApplicationName("Stego Detector")
        app.setStyle("Fusion")
        window = DetectorWindow()
        window.show()
        sys.exit(app.exec())


if __name__ == "__main__":
    main()
