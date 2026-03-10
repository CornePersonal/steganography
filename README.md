# StegoCrypt v2

**Compression-resistant steganography that fights to survive.**

Hide secret messages or files inside ordinary images — protected by military-grade encryption and error correction that survives JPEG recompression, WhatsApp/Telegram re-encoding, and format conversion. Includes a companion detection tool to scan images for hidden data.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Usage](#usage)
  - [StegoCrypt — Embed & Extract](#stegocrypt--embed--extract)
  - [Stego Detector — Find Hidden Data](#stego-detector--find-hidden-data)
- [Embedding Strength Guide](#embedding-strength-guide)
- [Tips & Best Practices](#tips--best-practices)
- [Technical Details](#technical-details)
- [License](#license)

---

## Features

### StegoCrypt (Embed & Extract)
- **AES-256-GCM encryption** — Password-based authenticated encryption with PBKDF2-SHA256 key derivation (200K iterations). Wrong passwords are detected instantly.
- **Reed-Solomon error correction** — Corrects up to 25 corrupted bytes per block (or 50 with erasure decoding). Interleaved across blocks for burst-error resistance.
- **3× spatial redundancy** — Every bit is embedded in 3 different locations with confidence-weighted majority voting.
- **PRNG-shuffled positions** — Bit positions are scattered using a password-seeded permutation. Without the password, the data is indistinguishable from image noise.
- **DCT-domain embedding** — Hides data in mid-frequency coefficients of 8×8 pixel blocks, the same domain JPEG uses internally, so embedded values survive compression.
- **Smart recovery engine** — Auto-detects embedding strength. Escalates through erasure decoding, bit-flip recovery, and alternate-step probing when standard decoding fails.
- **Text or file payloads** — Embed secret text messages or entire files (any type). Data is zlib-compressed before encryption.
- **Modern dark-themed GUI** — Drag-and-drop image loading, live capacity display, adjustable strength slider.

### Stego Detector (Detection & Analysis)
- **6 detection engines** running in parallel:
  1. **Chi-square statistical analysis** — Detects LSB replacement in the spatial domain
  2. **JPEG DCT histogram analysis** — Detects Jsteg/F5-style DCT coefficient manipulation
  3. **Stegano LSB reveal** — Attempts standard LSB message extraction
  4. **EXIF/metadata anomaly detection** — Finds hidden fields, base64 data, oversized thumbnails
  5. **File structure analysis** — Detects appended data, dual headers, embedded file signatures
  6. **StegoVeritas integration** — Trailing data extraction, binwalk carving, steghide, brute-force LSB
- **Batch scanning** — Drag and drop multiple images or entire folders
- **Exportable JSON reports** — Save detailed findings for documentation
- **CLI mode** — Script-friendly command-line interface for automation
- **Confidence scoring** — Each engine reports a detection confidence level

---

## How It Works

The embedding pipeline applies 5 layers of protection to your data:

```
Your message
   │
   ▼
┌──────────────────┐
│  zlib compression │  ← Maximizes capacity
└──────────────────┘
   │
   ▼
┌──────────────────┐
│  AES-256-GCM     │  ← Password-based authenticated encryption
└──────────────────┘
   │
   ▼
┌──────────────────┐
│  Reed-Solomon ECC│  ← Corrects up to 25 byte errors per block
└──────────────────┘
   │
   ▼
┌──────────────────┐
│  3× redundancy   │  ← Each bit stored 3 times, majority voted
└──────────────────┘
   │
   ▼
┌──────────────────┐
│  DCT embedding   │  ← Bits scattered across PRNG-shuffled
│  (8×8 blocks)    │    mid-frequency coefficients
└──────────────────┘
   │
   ▼
  Stego image (PNG)
```

The receiver only needs the **password** — embedding strength and all other parameters are auto-detected during extraction.

---

## Installation

### Requirements
- Python 3.10+

### Install dependencies

**For StegoCrypt (embed/extract):**
```bash
pip install PyQt6 numpy scipy cryptography reedsolo Pillow
```

**For Stego Detector (detection/scanning):**
```bash
pip install PyQt6 numpy Pillow exifread stegano stegoveritas python-magic-bin
```

**Install everything at once:**
```bash
pip install PyQt6 numpy scipy cryptography reedsolo Pillow exifread stegano stegoveritas python-magic-bin
```

> **Note:** `stegoveritas` is optional for the detector — the other 5 engines work without it. If not installed, that engine is simply skipped.

---

## Usage

### StegoCrypt — Embed & Extract

Launch the GUI:
```bash
python stego.py
```

#### Embedding a message
1. Open the **Embed** tab
2. Drag and drop (or click to browse) a cover image
3. Choose **Text** or **File** mode and enter your secret content
4. Set an encryption password
5. Adjust the **Embedding Strength** slider (default 16 is good for most cases)
6. Click **Embed & Save** and choose where to save the PNG output

#### Extracting a message
1. Open the **Extract** tab
2. Load the stego image
3. Enter the same password used during embedding
4. Click **Extract** — the decrypted message or file appears automatically

---

### Stego Detector — Find Hidden Data

#### GUI mode
```bash
python detect_embeddings.py
```

1. Drag and drop images (or an entire folder) into the drop zone
2. Optionally enable **Deep Scan** for thorough analysis (slower)
3. Optionally provide a password (used by steghide engine)
4. Click **Scan Images**
5. Review per-image results and the scan log
6. Click **Export Report** to save findings as JSON

#### CLI mode
```bash
# Scan a single image
python detect_embeddings.py --cli photo.png

# Scan a folder of images
python detect_embeddings.py --cli ./suspect_images/ --out results

# Deep scan with password
python detect_embeddings.py --cli photo.jpg --deep --password secret123
```

CLI arguments:
| Argument | Description |
|---|---|
| `target` | Image file or directory to scan |
| `--out DIR` | Output directory for results (default: `results`) |
| `--password PW` | Password for steghide extraction attempts |
| `--deep` | Enable deep analysis (LSB brute-force, carving, transforms) |

---

## Embedding Strength Guide

The strength slider controls the quantization step size used during DCT embedding. Higher values create more robust embeddings at the cost of slightly more visible artifacts.

| Step | Level | Survives |
|------|-------|----------|
| 8–10 | Subtle | Light compression (JPEG quality ≥ 85) |
| 11–16 | Balanced | Moderate compression (JPEG quality ≥ 75) |
| 17–24 | Strong | Heavy compression (JPEG quality ≥ 60) |
| 25–32 | Maximum | Aggressive compression (JPEG quality ≥ 50) |

**Default: 16** — a good balance of invisibility and robustness for most use cases.

---

## Tips & Best Practices

- **Image size matters** — Use images at least 1000×1000 pixels for longer messages. Capacity scales with image area.
- **Messaging apps** — When sending via WhatsApp or Telegram, send the image as a **Document/File** for lossless delivery. If sending as a photo, enable "Auto-resize for messaging apps" and use strength ≥ 20.
- **Password is everything** — The receiver only needs the password. Strength, format, and all other parameters are auto-detected.
- **Output format** — Stego images are always saved as PNG (lossless). The embedded data survives if the PNG is later converted to JPEG at reasonable quality.
- **File embedding** — You can embed any file type (PDFs, ZIPs, documents, etc.), not just text. Files are compressed before encryption.
- **Detection resistance** — StegoCrypt uses frequency-domain embedding with PRNG scattering, which is inherently harder to detect than spatial LSB methods. The companion detector is designed to catch *other* steganography techniques.

---

## Technical Details

### Encryption
- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key derivation:** PBKDF2-HMAC-SHA256, 200,000 iterations, 16-byte random salt
- **Nonce:** 12 bytes, randomly generated per embedding

### Error Correction
- **Codec:** Reed-Solomon with 50 parity symbols per 255-byte block
- **Capacity:** Corrects ≤25 byte errors or ≤50 erasures per block
- **Interleaving:** Byte-level interleaving across blocks for burst-error resistance
- **Recovery strategies:** Standard decode → erasure decode → cumulative bit-flipping (up to 40 flips) → alternate quantization step probing

### Embedding
- **Domain:** DCT (Discrete Cosine Transform) frequency domain
- **Block size:** 8×8 pixels
- **Coefficients used:** Zigzag positions 3–15 (13 mid-frequency coefficients per block)
- **Redundancy:** Each bit stored 3× with confidence-weighted majority voting
- **Header:** 5-byte self-describing header (RS length + quantization step), repeated 7× for robustness
- **Position shuffling:** SHA-256 password hash → NumPy PRNG seed → permutation of all embeddable positions

### Payload Format
```
MAGIC (4 bytes: "STGC") | Payload Length (4 bytes, big-endian) | Payload
```
Where payload is: `type_byte | compressed_encrypted_data`
- Type `0x00`: zlib-compressed text
- Type `0x01`: filename length (2 bytes) + filename + zlib-compressed file data

---

## License

[MIT License](LICENSE) — Copyright (c) 2026 Corné Kotze
